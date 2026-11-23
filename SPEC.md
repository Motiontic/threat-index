# search-shards: nightly search index job and the public `GET /v1/search`

## Why

`GET /v1/search` returns 501 and the `search-index` job throws `NotImplementedError`. Full-text search in D1
(FTS5) writes many shadow rows per document and would eat the daily write budget, so the plan
(`docs/IMPLEMENTATION_PLAN.md` §8, "Search design") keeps the index in R2: an E2B job builds an inverted
index of the hot set each night as `lookup/search/<prefix>.json`, and the API reads one shard per query term,
intersects them, and adds a small live delta from D1 for rows changed since the build. Exact IDs skip the
index. This change builds both halves, plus the A–Z index files and `sitemap.xml`, which the same job writes.

Other features are built at the same time. The heavy-jobs change adds the `search-index` kind to the API's
job unions and adds the sandbox routes this job calls (below). The public-API change owns `credits.ts`,
`resolve-key.ts`, `cache.ts` and the entries and index routes. Code against the contracts here and test
with fakes; never rely on another branch's code being merged.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/search.ts` | `GET /v1/search` → `notImplemented` (501). Mounted after `clerkMiddleware()` (public, no user needed) |
| `apps/api/test/api.workers.test.ts` | Asserts `/v1/search?q=x` returns 501 |
| `e2b/jobs/src/jobs/search-index.ts` | Throws `NotImplementedError`. `run.ts` calls `api.complete({ ok: true })` after `run()` returns |
| `e2b/jobs/src/client.ts` | `createJobApi`: signed `upload-urls`/`complete` POSTs only; no object or rows calls |
| `POST /internal/jobs/:id/complete` | Fails the job with `manifest missing` unless `inbox/<id>/manifest.json` exists |
| `@ti/core/search`, `@ti/core/api`, `r2-keys` | `searchTerms`, `shardPrefix`, `searchShardKey`, `SearchShard`; `SearchHit`, `SearchResponse`, `Credit`, `IndexLetterResponse`; `indexLetterKey`, `sitemapKey` |
| `@ti/core/ids` | `normaliseId` (CVE upper case, GHSA lower-case suffix) |
| `ti_vulns.vulns` | PK `key`; `title`, `summary`, `published`, `modified` (NOT NULL), `cvss`, `kev_added`, `hot`, `sources` (JSON), `kind`. No index on `modified` |
| `ti_advisories.advisories` | PK (`source`, `source_id`), `vuln_key` indexed, `status` active/withdrawn/rejected |
| API bindings | `DB_VULNS`, `DB_ADVISORIES`, `BUCKET` (R2). No `DB_SIGNALS` binding |
| Web (`/search`) | Sends `q`, repeatable `type` (`vuln`, `breach`, `ai`, `mal`, `tech`, `term`), `sig=kev`, `sort=rel\|new` |

## What to build

Touch only `e2b/jobs/src/jobs/search-index.ts` (+ `search-index.test.ts` next to it),
`apps/api/src/routes/search.ts`, new `apps/api/src/lib/search*.ts`, a new
`apps/api/test/search.workers.test.ts`, and in `apps/api/test/api.workers.test.ts` only delete the three
lines that expect `/v1/search` to return 501. Don't edit `client.ts`, `run.ts`, `types.ts`, `internal-jobs.ts`,
`presign.ts`, `index.ts`, `credits.ts`, `resolve-key.ts`, migrations, Wrangler configs or any `package.json`.
Add no dependency.

### 1. Sandbox contract this job relies on (added by the heavy-jobs change)

All calls are signed like today's: headers `x-ti-timestamp` and `x-ti-signature` =
`signRequest(job.hmac, METHOD, path, ts, body)`, where `path` has no query string and `body` is `''` for GET.

- `GET /internal/jobs/:id/rows/<table>?after=<next>&limit=<n ≤ 1000>` → `{ rows: object[], next: string | null }`,
  rows ordered by primary key, column names as in D1 (snake_case). Pass `next` back as `after` verbatim; stop
  at `null`. Tables used here: `vulns`, `advisories`.
- `PUT /internal/jobs/:id/objects/<key>` (body ≤ 50 MiB) → 2xx. The `search-index` kind must be allowed to
  write `lookup/search/`, `lookup/index/`, `sitemap.xml` and its own `inbox/<id>/`. Say in the PR that this
  prefix list is a dependency on the heavy-jobs change.

If `client.ts` on your base already exports functions for these two calls, use them. Otherwise write a
minimal signed client inside `search-index.ts` with the same retry rule as `client.ts` (3 retries with
500 ms × 2ⁿ backoff on network errors and 5xx; throw at once on 4xx). The job never calls `complete` itself.

### 2. Index builder: `e2b/jobs/src/jobs/search-index.ts`

```ts
export interface IndexIo {
  rows(table: 'vulns' | 'advisories', after: string | null, limit: number):
    Promise<{ rows: Record<string, unknown>[]; next: string | null }>;
  put(key: string, body: string, contentType: string): Promise<void>;
}
export interface BuiltIndex {
  shards: Map<string, SearchShard>;                // prefix → shard
  letters: Map<string, IndexLetterResponse>;       // 'a'..'z', '0' → page (all 27 always present)
  sitemap: string | null;                          // null when no site origin is set
}
/** Pure. No I/O, no clock: `builtAt` is passed in. */
export function buildIndex(vulns: VulnRow[], advisories: AdvisoryRow[], builtAt: string,
  opts?: { siteOrigin?: string }): BuiltIndex;
export function jobIo(job: Job, deps?: { fetch?: typeof fetch; now?: () => number; sleep?: (ms: number) => Promise<void> }): IndexIo;
export async function run(job: Job, ctx: JobContext, io: IndexIo = jobIo(job)): Promise<void>;
```

`run` takes `builtAt` = now (ISO) **before** paging starts, so a row changed during the build is still
caught by the API's live delta. It pages both tables at `limit=1000`, calls `buildIndex`, uploads every
shard (`searchShardKey(prefix)`, `application/json`), all 27 letter files (`indexLetterKey`), `sitemap.xml`
(`application/xml`) when built, then an empty inbox manifest `{ jobId, createdAt, chunks: [] }` at
`inboxManifestKey(job.id)` so `complete` accepts the job. It logs counts (rows, shards, largest shard bytes,
trimmed terms) through `ctx.log`. Site origin comes from `process.env.SITE_ORIGIN` (must start with
`https://`, no trailing slash); without it the sitemap is skipped with a log line.

Rules for `buildIndex`:
- Only rows with `hot = 1`. Rows must have a string `key`, `title` and `modified`; skip and count others.
- A vuln whose advisories (by `vuln_key`) all have status `rejected` or `withdrawn` is left out of shards,
  letters and the sitemap. A vuln with no advisories is kept.
- Terms per vuln: `searchTerms` of `title`, `summary`, `kind`, and each CWE id in `cwe` (JSON array; bad
  JSON → none). **ID columns are not indexed:** the vuln's own key and its advisories' `source_id`s are never
  added as terms, because every CVE id shares the `cv` prefix and would make one huge shard. IDs are found
  by the API's exact-ID path (section 3). A term that only appears inside a title or summary is indexed.
- Each term goes to the shard `shardPrefix(term)`. Postings are unique keys, sorted.
- A term with more than `MAX_POSTINGS = 2000` keys is written as `terms[term] = []`, meaning "too common:
  ignore this term". After that, if a shard's JSON is over `MAX_SHARD_BYTES = 6 MiB`, empty its largest
  posting lists in turn until it fits, and count them.
- `docs` holds one `SearchHit` per key the shard references: `key`, `title`, `summary` cut to 160 characters,
  `cvss`, `exploited` = `kev_added` is set, `published`. Every shard gets `builtAt`.
- Letters: first character of the lower-cased title; `a`–`z` go to that letter, everything else to `0`.
  Items `{ key, title }` sorted by title (`localeCompare` with `sensitivity: 'base'`), then key; at most
  20,000 per letter, no `cursor`.
- Sitemap: `/`, `/search`, `/sources`, `/index/<letter>` for the 27 letters, then `/e/<encodeURIComponent(key)>`
  for at most 49,000 entries, most recently modified first, with `<lastmod>` = the date part of `modified`.
  XML-escape every value.

Node tests (`search-index.test.ts`, no network, fake `IndexIo`): terms land in the right shard; IDs are not
terms; a rejected-only vuln is dropped; `hot = 0` is dropped; the 2,000-posting rule writes `[]`; the size cap
trims; letters include `0` and empty letters; sitemap escaping and the 49,000 cap; `run` pages with `next`
until `null`, uploads every key exactly once, writes the manifest last, and fails on a refused PUT; `jobIo`
signs requests that `verifyRequest` accepts (with `deriveJobKey`) and retries a 503.

### 3. Search route: `apps/api/src/routes/search.ts` and `apps/api/src/lib/search*.ts`

Split into `lib/search-params.ts` (parse and validate, cursor), `lib/search-engine.ts` (exact ID, shards,
delta, live query, sort), `lib/search-credits.ts` and a thin route. Use `SearchResponse` as the body.

**Parameters.** `q` (≤ 200 chars, trimmed), repeatable `type` in {`vuln`,`breach`,`ai`,`mal`,`tech`,`term`},
`sig` in {`kev`}, `sev` in {`critical` ≥ 9.0, `high` 7.0–8.9, `medium` 4.0–6.9, `low` 0.1–3.9}, `year` (4
digits, 1999–2100), `sort` in {`rel`,`new`} (default `rel` with a query, `new` without), `limit` 1–50
(default 20), `cursor`. Anything invalid → 400 `{ "error": "invalid_query" }`. Only the first 8 terms of
`searchTerms(q)` are used.

**Filters where data allows.** All results are `vulns` rows. `type`: `mal` = keys starting `MAL-`, `vuln` =
the rest; `breach`, `ai`, `tech`, `term` match nothing yet (200 with no hits). `sig=kev` = `exploited`.
`sev` from `cvss` (no CVSS never matches a `sev` filter). `year` from `published`. Repeated values of one
filter are OR'd; different filters are AND'd.

**Order of work.**
1. **Exact ID.** If `q` is one term with a digit, 4–80 characters, matching
   `^[A-Za-z][A-Za-z0-9]*[-:_][A-Za-z0-9._:-]+$`: look up `vulns.key = normaliseId(q)`; if absent, look up
   `advisories WHERE source IN (<every registry source id>) AND source_id IN (?, ?)` with the raw and
   normalised ID (this uses the primary key index), take its `vuln_key`, and read that vuln. A hit (after
   filters) returns it alone with `total: 1`. No hit falls through to step 2.
2. **Shards.** Read `searchShardKey(shardPrefix(t))` from `BUCKET` once per distinct prefix, in parallel.
   Ignore an object over 16 MiB or one that fails a shape check (log it, treat as missing). A term whose
   posting list is `[]` is ignored. The candidate set is the intersection of the other terms' lists; a term
   absent from an existing shard matches nothing. Keep the shard `docs` as the hits.
3. **Live delta.** `builtAt` = the oldest `builtAt` of the shards read. Query `vulns` where `hot = 1 AND
   modified > ?builtAt` and, for each term, the lower-cased `key || ' ' || title || ' ' || summary` `LIKE
   %term%` (with `%`, `_` and `\` escaped, `ESCAPE '\'`), `ORDER BY modified DESC LIMIT 500`. Confirm each
   row in code with `searchTerms` (so `log` does not match `login`), then add or replace its hit.
4. **No index yet.** If every shard read was missing, run the step 3 query without the `modified` bound
   (`LIMIT 1000`). Search works on a fresh staging bucket before the first build.
5. **Empty `q`.** Skip steps 1–4 and query `vulns` in SQL with the filters, `hot = 1`, the sort, and
   `LIMIT/OFFSET`; `total` from a `COUNT(*)` with the same `WHERE`.
6. Apply filters, sort, and slice the page. `rel`: count of query terms in `searchTerms(title)` desc, then
   `exploited`, `cvss` desc, `published` desc, `key`. `new`: `published` desc (missing last), then `key`.
   At most `MAX_CANDIDATES = 5000` hits are kept before sorting; `total` is the count after filters.
7. **Hydrate the page.** One `SELECT key, title, summary, cvss, kev_added, published, sources FROM vulns
   WHERE key IN (…)` (≤ 50 keys): refresh each hit's fields, drop keys that are gone or no longer hot, and
   collect `sources` for credits.

**Cursor.** Opaque base64url of `{ v: 1, o: <offset>, f: <fingerprint> }`, where the fingerprint is a short
hash of the normalised parameters other than `cursor` and `limit`. A cursor for a different query, a
malformed one, or an offset over 1,000 → 400 `invalid_query`. `cursor` is present only when more hits remain.

**Credits.** `lib/search-credits.ts` builds `Credit[]` (`sourceId`, `name`, `text` from `SOURCE_BY_ID`) for the
union of `sources` on the page, adding the NVD notice (`NVD_NOTICE`) when `nvd` is used, as `credits.ts`
does today. Every response carries `credits`, even an empty page (`[]`).

**Cache.** Responses never vary on auth. Build a cache key from the URL with sorted parameters and no
headers; serve from `caches.default` when present; otherwise compute, set
`cache-control: public, max-age=60`, and `put` through `executionCtx.waitUntil`. 400s are not cached.

**Errors.** A D1 or R2 failure → 503 `{ "error": "search_unavailable" }`, logged as one JSON line with no
query text beyond 200 characters. Never return a stack trace.

Workers tests (`search.workers.test.ts`, local D1 and R2): seed `vulns` and `advisories` rows and put one
shard per prefix into `BUCKET`. Cover: exact CVE (any case); a GHSA alias through `advisories`; a two-term
query intersects; a stop-word `[]` term is ignored; a row modified after `builtAt` appears without being in a
shard; a non-hot row never appears; no shards at all still finds a seeded row; empty `q` with `sig=kev`;
`sev`, `year` and `type=mal` filters; `type=breach` → 200 empty; `sort=new`; paging with `cursor` to the end
and a foreign cursor → 400; `q` over 200 chars → 400; `credits` names the seeded sources and the NVD notice.

## Not in scope

- Deleting shards whose prefix vanished since the last build (no delete route); stale terms there point at
  keys that step 7 drops. Package names (not in D1 yet), signals other than KEV, and techniques.
- `lookup/vuln/*` and `lookup/pkg/*` (other jobs), a sitemap index past 49,000 entries, the cron that starts
  this job, and its allowed prefixes (heavy-jobs change).
- An index on `vulns.modified` (no migrations now); until then steps 3–5 scan the hot set and rely on the
  60-second cache. Caching parsed shards in the isolate. The web page switching to the API.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass; the new Node and Workers tests listed above exist and pass.
2. Only the files named in "What to build" change; `git diff --stat main -- packages apps/api/src/index.ts`
   shows nothing, and no `package.json` or `pnpm-lock.yaml` changes.
3. `buildIndex` on the test fixture produces no shard holding a vuln key or advisory ID as a term.
4. Proof saved: test output; one `wrangler dev` run of the api on port 8700 with local D1 and R2 seeded
   (script in the PR), and `curl` results for an exact CVE, a GHSA alias, a word query with and without a
   shard present, a filtered empty-`q` browse, page 2 by cursor, a bad parameter (400), and a repeat request
   showing the cache hit; and a `node --experimental-strip-types` run of the job against a local fake API
   listing every uploaded key.
5. The PR states the dependencies on the heavy-jobs change (rows and object routes, `search-index` in the
   job unions, write prefixes, `SITE_ORIGIN` in the sandbox env) and that `/v1/search` returns 200 on
   staging before the first build.
