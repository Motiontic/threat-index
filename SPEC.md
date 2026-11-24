# search-scale: search and the A–Z index must work with the full data set

## Why

Staging now holds about 211,000 hot entries. The nightly `search-index` job (`e2b/jobs/src/jobs/search-index.ts`)
and its readers in the API were sized for far fewer, and two things broke. Measured on staging on 24 Nov 2026:

1. **Search returns nothing for many terms.**
   - `lookup/search/lo.json` was written with 2,218 terms, every list empty, and no docs. The shard went over
     `MAX_SHARD_BYTES` (6 MiB), and the trimming step emptied the lists. `ap.json` and `la.json` are about 5 MB
     each, so most busy prefixes are at or over the cap.
   - Any term with more than `MAX_POSTINGS` (2,000) entries is written as an empty list ("too common"). The API
     (`apps/api/src/lib/search-engine.ts`) then ignores the term. A query made only of such terms returns
     `total: 0`. `q=apache` and `q=log4j` both return no hits; `q=langflow` returns 241.
2. **The A–Z index page fails.** `lookup/index/<letter>` holds up to `MAX_LETTER_ITEMS` (20,000) items in one
   object. `GET /v1/index/a` returns all 20,000 (2.5 MB), and the web app answers `/index/a` with 502
   ("response too large").

## What to build

Read `docs/decisions/0004-search-shards-instead-of-fts.md`, the writer, `packages/core/src/search.ts` and the
API reader first. Keep the approach (nightly R2 shards, live D1 delta); fix how it scales.

1. **No shard is ever emptied for size.** Choose a layout where every shard object stays under the cap with
   500,000 hot entries, for example splitting a busy prefix into deeper prefixes with a small pointer or
   manifest the API can follow, or storing docs apart from postings. The writer must fail the job, not write an
   empty or partial shard, if it still cannot fit one.
2. **Common terms still return results.** A term over `MAX_POSTINGS` keeps its `MAX_POSTINGS` most recently
   modified entries and is marked as truncated, instead of an empty list. The API treats a truncated list as a
   normal list. A query of only common terms returns hits.
3. **The API reads the new layout** and still handles a bucket that holds no index (live query) and one that
   holds only the old layout (treat old shards as absent, never as "matches nothing"). Keep
   `MAX_SHARD_OBJECT_BYTES` and the shape checks. At most a small, fixed number of R2 reads per query term.
4. **A–Z index in pages.** The writer writes each letter in pages of at most 500 items, and
   `GET /v1/index/:letter` returns at most 500 items with a `cursor` for the next page until the letter is
   done. The existing D1 fallback keeps working when no page exists. `IndexLetterResponse` keeps its shape.
   The web route `/index/<letter>` already follows `cursor`; change it only if the cursor format needs it.
5. **Old objects.** After a successful build the job deletes index objects of the old layout that the new
   layout no longer writes (the signed object DELETE route exists), so stale shards cannot be read.
6. **Tests.**
   - Writer: a synthetic build of 250,000 entries with a realistic skew (a few terms in more than half the
     titles, many terms sharing one two-letter prefix) writes no shard over the cap, no empty list for a term
     that has entries, and letter pages of at most 500 items. Keep it fast enough for `pnpm build`, or put it
     where the slower tests run.
   - API: a too-common single-term query returns hits; a term in a split or deep shard is found; an old-layout
     bucket falls back to the live query; `/v1/index/a` pages through every item with no page over 500.
7. Update `docs/decisions/0004-search-shards-instead-of-fts.md` (or add a new decision) and the "Search
   design" part of `docs/IMPLEMENTATION_PLAN.md` to describe the new layout and limits.
8. Add one check to `scripts/smoke-staging.mjs`: `api /v1/search?q=apache` returns at least one hit.

## Not in scope

D1 full-text search, new dependencies, migrations, ranking changes, the sitemap, other jobs.

## Files this loop owns

`e2b/jobs/src/jobs/search-index*.ts`, `packages/core/src/search*.ts`, `packages/core/src/r2-keys*.ts`,
`packages/core/src/api.ts` (only if a type must change), `apps/api/src/lib/search-engine.ts`,
`apps/api/src/routes/index-letter.ts`, `apps/api/src/routes/search.ts`, their tests under `apps/api/test/`,
`apps/web/app/routes/index-az.tsx` and its test, `scripts/smoke-staging.mjs`, and the two docs. Do not touch
`pnpm-lock.yaml`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. The tests in section 6 pass, and the proof records the largest shard size and the largest letter page from
   the 250,000-entry synthetic build.
3. No code path writes an empty list for a term that has entries.
