# jobs-v2: first loads for list and git sources, a faster first load, big-file, and the nightly and daily jobs

## Why

The E2B bridge works end to end, but four gaps stop it from carrying real sources. `first-load` parses one
downloaded file, so the `changelist` and `git` patterns, which hand off a changes list or a `.tar.gz` repository
archive on a first run, get a job that can't read what it was given. A CISA KEV first load (about 1,500 records)
took about 12 minutes on staging, far too slow for the larger sources. `big-file`, the kind the patterns ask
for on a large update, is still a stub, so ti-api refuses it with `501`. And no cron starts `nightly-fold`,
`search-index` or `epss-diff`.

This change fixes all four in the sandbox jobs, ti-api's job routes and the collector's crons.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `e2b/jobs/src/jobs/first-load.ts` | Downloads `job.url` (else `pull.heavy.url`, `pull.fingerprint.url`, `urls[0]`) with `download()`, `JSON.parse`s it when the path or type says JSON, calls `parse(input)` once, links in batches of 5,000, writes one lake part and the inbox |
| `sandboxLinkDeps` (same file) | `read()` pages the whole table through `api.allRows` on first use, one table at a time. `lookupCold()` does one signed `GET lookup/vuln/<shard>.json` per distinct shard (4,096 shards), in turn, as the linker asks; those files don't exist yet, so each is a 404 |
| `e2b/jobs/src/client.ts` | `ROWS_PAGE = 500` (the route allows 1,000); every call is sequential |
| `e2b/jobs/src/lib/inbox.ts` | Chunks of `MAX_ROWS_PER_CHUNK` (500, `@ti/core/inbox`), uploaded one after another, manifest last |
| `e2b/jobs/src/jobs/big-file.ts` | Throws `NotImplementedError` |
| `apps/api/src/lib/e2b.ts` | `ENABLED_JOB_KINDS` has no `big-file`; `GLOBAL_JOB_KINDS` says the collector never starts them |
| `apps/api/src/routes/internal-jobs.ts` | `POST /internal/jobs`: `requestId` must match `JOB_ID` (a ULID, optional `-N`) and becomes the job id; the same id again returns `200 { existing: true }`, also after the job finished. Stores the request (with its target `cursor`) at `jobs/<id>/request.json`; `complete` commits that cursor. Priority is `first-load` for that kind, else `steady` |
| Patterns (`packages/patterns/src`) | `changelist` hands off `url = listUrl` (first run: `first-load`; more than 4 ranges of changes: `big-file`) or one item URL (`big-file`, item over the size limit). `git` hands off `https://github.com/<repo>/archive/<sha>.tar.gz` (`first-load` or `big-file`) or one raw file URL (`big-file`). `jobKind()` defaults to `big-file` |
| Parsers | Take the Worker's item bodies: `ChangeItem { ref, time, text }` (`@ti/patterns/changelist`) and `GitFile { path, status, text }` (`@ti/patterns/git`) |
| `apps/collector/src/index.ts` | `scheduled()` runs `plan()`, plus `runWatchdog()` on `45 14 * * *`. `30 2 * * *` plans nothing |
| `apps/collector/src/heavy.ts` | `startHeavyJob(env, req: JobRequest, now)` signs and sends `POST /internal/jobs` |

## What to build

Touch only `e2b/**`, `apps/collector/**`, `apps/api/src/routes/internal-jobs.ts`, `apps/api/src/lib/e2b.ts`,
their existing test files (`apps/api/test/internal-jobs*.workers.test.ts`), and `pnpm-lock.yaml` for the one
dependency below. Don't edit `packages/**`, migrations or `docs/**`. One new dependency only:
`"@ti/patterns": "workspace:*"` in `e2b/jobs/package.json`, so the job uses the Worker's own `globToRegExp`,
`parseCsvLine` and item types rather than copies.

### 1. Profile, then fix the first-load speed

Before changing anything, measure. Add `e2b/jobs/src/bench-first-load.ts` (script `bench:first-load`) that
runs `first-load` for `cisa-kev` against a fake API and a fake `fetch`:

- input: the KEV fixture's record repeated to 1,500 entries with distinct CVE ids, served by the fake fetch;
- fake API: seeded with 20,000 `vulns`, 5,000 `advisories` and 30,000 `signals` rows, no `lookup/vuln/` objects;
  every call waits a fixed latency (default 150 ms, `--latency-ms`; an assumed E2B-to-Cloudflare signed round
  trip) and honours concurrency (parallel calls overlap); fake DuckDB/lake writer;
- output: wall time, calls per route (`rows`, `get-object`, `list`, `put-object`) and the peak calls in flight.

Run it on the unchanged code first and save the output as the "before" profile. The expected cause is
`lookupCold` (one 404 per shard, about 1,200 for 1,500 cold CVEs, in series) and full-table paging at 500 rows;
if the numbers say otherwise, fix what they show and say so. Then:

- **Cold lookups in bulk.** `sandboxLinkDeps(ctx, now)` gains `prime(records: ParsedRecord[]): Promise<void>`,
  called before each `link()` batch. It lists `lookup/vuln/` once per job (`api.list`, ≤ 5 pages) to learn which
  shards exist, then GETs only the existing shards those records need, ≤ 8 at a time. `lookupCold` never
  GETs a shard that the listing didn't show; a shard missing from the cache after priming returns `null`.
- **Rows.** `ROWS_PAGE = 1000`. The first `read()` loads all three tables at once (`Promise.all`), each still
  keyset-paged in order. Rows a finished batch merged still win over API rows.
- **Uploads.** `writeInbox` uploads chunks ≤ 4 at a time; the manifest is still written last, after every chunk
  succeeded. Chunk size stays 500 (`@ti/core/inbox`).
- Add a shared helper `e2b/jobs/src/lib/pool.ts`:
  `mapLimited<T, R>(items: readonly T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]>`
  (results in input order; the first rejection rejects the whole call and starts no new work).

**Target:** the bench at 150 ms latency finishes KEV in under 2 minutes. Save the "after" output next to the
"before" one. The staging run is checked after merge (the loop has no E2B credentials); say so in the PR.

### 2. `first-load`: three input shapes

`run(job, ctx, deps)` picks the shape from `source.pattern` and the URL; export
`inputShape(source: SourceConfig, url: string): 'file' | 'changelist' | 'change-item' | 'archive' | 'git-file'`:

- `changelist` and `url === pull.changelist.listUrl` → **changelist**; another URL → **change-item**.
- `git` and the URL is `https://github.com/<pull.git.repo>/archive/<40-hex>.tar.gz` → **archive**; another URL
  → **git-file**.
- anything else → **file**: today's behaviour, unchanged.

The job reads `jobs/<id>/request.json` (`api.getObject`) for `cursor` (the target) and `from` (section 4).
Every shape yields `ParsedRecord[]`; linking, the lake part and the inbox stay as today (with section 1).
Parsing: one `parse()` call per document; a throwing document is skipped and counted; if every document
throws, the job fails with the first error. Logs carry counts only, never bodies or URLs with queries.

**changelist** (`e2b/jobs/src/lib/changelist.ts`):

- Download the list with `download()` to scratch, read it line by line with `parseCsvLine`, keep rows whose
  `timeColumn` parses as a date and whose `refColumn` is set (the Worker's rule).
- Window: lines `(time, ref)` greater than `from` (a `[time, ref]` JSON pair, compared like the pattern's `cmp`)
  and not greater than the target cursor's pair. With no `from`, everything up to the target.
- **Cap: 10,000 documents per job** (`MAX_LIST_DOCS`). A first load over the cap takes the newest 10,000 and
  logs `older` (how many it left); history before that is later work. An update (`big-file`) over the cap fails
  with `too many changes: <n>`, so the cursor doesn't move and the watchdog reports it.
- Fetch each `itemUrl` with `{ref}` filled in (`encodeURIComponent` per path segment, refusing `.`/`..`, as
  `fillTemplate` does), through `mapLimited` with ≤ 8 in flight and a polite rate of ≤ 10 requests a second
  per job (`lib/pool.ts`: `rateGate(perSecond, deps.sleep, deps.now)`). Use `download()`'s rules: `https:`
  only, ≤ 5 redirects, 3 retries on network errors and 5xx, user agent `USER_AGENT`. A `429` waits
  `Retry-After` (≤ 60 s, default 30 s) and counts as a retry. A document over 10 MiB is skipped and counted.
  `404`/`410` → `text: null` (a deleted document, as in the Worker). Another `4xx` fails the job.
- Each document is parsed as `ChangeItem { ref, time, text }`.

**change-item**: one document. `ref` and `time` come from the target cursor's pair (the pattern sets it to that
item); no pair → fail. Fetched and parsed as above.

**archive** (`e2b/jobs/src/lib/tar.ts`, no new dependency):

```ts
export interface TarEntry { path: string; size: number; text(): Promise<string> }
/** Streams a gzipped tar from `body`, calling `onEntry` for each regular file. Never writes to disk. */
export async function readTarGz(body: ReadableStream<Uint8Array>, onEntry: (e: TarEntry) => Promise<void>,
  limits?: { maxEntryBytes?: number; maxTotalBytes?: number }): Promise<{ files: number; skipped: number }>;
```

- Fetch with the same `https:`/redirect/retry rules, then `Readable.fromWeb` → `createGunzip` → a ustar reader.
  Handle regular files (`0`, `\0`), directories (`5`, ignored), pax headers (`x` per entry, `g` global, `path=`
  only) and GNU long names (`L`). Skip and count links, devices and anything else. Check each header's checksum;
  a bad one fails the job. Two zero blocks end the archive.
- Strip the first path component (`<repo>-<sha>/`). Refuse a path with `..`, a leading `/` or `\0` (skip and
  count). Keep a file only if its extension is a data extension (`json csv md xml yaml yml txt`, the git
  pattern's set) and a `pull.git.include` glob (`globToRegExp`) matches.
- Limits: an entry over 10 MiB is skipped and counted (its bytes are still drained); more than 4 GiB unpacked in
  total or more than 400,000 kept files fails the job. The gzip stream is read once; nothing is buffered beyond
  the current entry.
- Each kept file is parsed as `GitFile { path, status: 'added', text }`.
- An update from an archive (`big-file`) re-parses every included file. Files deleted upstream are not
  deleted here; that is later work.

**git-file**: one raw file URL; `path` is the part after `<repo>/<sha>/`, parsed as one `GitFile`
(`status: 'modified'`).

### 3. `big-file` = `first-load` with update semantics

Decision: keep `big-file` and make it the same code, so no source or pattern changes. `jobs/big-file.ts`
calls the shared runner with `mode: 'update'`. The differences are only these: the changelist window starts at
`from`, the over-the-cap rule fails instead of trimming, and ti-api loads its chunks with `steady` priority
(already the rule for every kind but `first-load`). The cursor rule is unchanged: ti-api commits the target
cursor only on `complete({ ok: true })`. Sources that set `pull.jobKind: 'first-load'` keep it.

In `apps/api/src/lib/e2b.ts` add `big-file` to `ENABLED_JOB_KINDS` and fix the `GLOBAL_JOB_KINDS` comment
(the collector starts them on its crons). In `POST /internal/jobs`, for the source kinds, read the source's
stored cursor from `ti_control.cursors` and add it as `from` to `jobs/<id>/request.json` (absent when there is
none). Nothing else in the route changes. Update `e2b/README.md` (kinds, shapes, limits, crons).

### 4. The crons start the nightly and daily jobs

New `apps/collector/src/daily-jobs.ts`:

```ts
export const DAILY_JOBS: Record<string, readonly DailyKind[]>; // '30 2 * * *' → nightly-fold, search-index; '45 14 * * *' → epss-diff
export type DailyKind = 'nightly-fold' | 'search-index' | 'epss-diff';
/** A ULID-shaped id: time part = UTC midnight of `day`, random part = first 80 bits of SHA-256(`${kind}:${day}`). */
export function dailyJobId(kind: DailyKind, day: string): Promise<string>;
export function startDailyJobs(cron: string, at: Date, env: Env, deps: { startJob: typeof startHeavyJob; log }): Promise<void>;
```

- `dailyJobId` must match ti-api's `JOB_ID` regex (Crockford base32, no `I L O U`), so a second start the
  same day, from a retried or doubled cron, gets `200 existing` and never a second sandbox.
- Requests: `nightly-fold` `{ kind, reason: 'nightly', requestId, day: <yesterday UTC> }`; `search-index`
  `{ kind, reason: 'nightly', requestId }` with `day` = today for the id; `epss-diff` `{ kind, sourceId: 'epss',
  reason: 'daily', requestId }`. `day` is taken from `event.scheduledTime`, never `Date.now()`.
- `epss-diff` is skipped (logged) when `readSourceSettings` says `ingest: false` for `epss`.
- Each job is started on its own; one failure doesn't stop the next. `index.ts` runs `plan()`, then
  `startDailyJobs()`, then the watchdog, each in its own `try`, and rethrows the first error.
- `heavy.ts`: widen the request type to `JobRequest | GlobalJobRequest` (a local type:
  `{ requestId; kind: 'nightly-fold' | 'search-index'; reason; day? }`); signing and error mapping are unchanged.
- `planner.ts`: the `30 2 * * *` comment points at `daily-jobs.ts`.

### 5. Tests

`pnpm test` (Node) for `e2b/jobs`, `pnpm test:workers` for the collector and ti-api. No test reaches the
network: fakes for `fetch`, the API and DuckDB; archives are built in the test with a small ustar writer in
`test-support.ts`; list and item bodies come from `fixtures/red-hat/` and `fixtures/msrc/` (`changes.csv` and
the CSAF files); git files from `fixtures/avid/`.

- **pool:** order kept, never more than `limit` in flight, first rejection stops new work; `rateGate` spaces
  calls with a fake clock.
- **changelist:** a first load walks the list, fetches every listed document, parses each (csaf), and writes rows;
  in flight ≤ 8; a 404 document becomes `text: null`; a 429 waits and retries; the cap trims a first load to the
  newest and fails an update; an update's window starts after `from` and stops at the target.
- **change-item:** ref and time from the cursor; no cursor → fails.
- **archive:** a gzipped tar with included files, a non-matching file, a `.py` file, a symlink, a `../` path, a pax
  long name and an over-size entry: only the included data files are parsed (avid), counts are logged; a bad
  checksum fails; the stream is never written to disk (scratch dir stays empty).
- **shape choice:** `inputShape` for each pattern and URL; KEV still runs the `file` path (existing tests pass).
- **speed:** with the counting fake API, KEV issues no `get-object` for a shard the listing didn't show, pages
  rows at 1,000, and loads the three tables concurrently; inbox chunks overlap but the manifest is last.
- **big-file:** runs end to end on a changelist update; `jobs/big-file.ts` no longer throws.
- **ti-api:** `big-file` starts (no `501`); `request.json` holds `from` when a cursor exists and none when not.
- **collector:** `dailyJobId` matches `JOB_ID`, is stable per kind and day and differs across both; the 02:30
  cron sends two signed requests (nightly-fold with yesterday) and the 14:45 cron one (`epss-diff`, `sourceId:
  'epss'`); the same cron twice sends the same ids; a failing first start still sends the second; KV
  `ingest:false` skips EPSS; other crons start nothing; watchdog still runs on 14:45.

## Not in scope

- History older than the newest 10,000 changes, and resuming one large first load across several jobs.
- Deleting rows for files removed upstream; a keyed rows lookup route (paging the hot set is fine at today's
  size); the loader's own throughput and budget deferrals.
- Retrying a nightly or daily start that failed (the next day starts afresh; the run is in the logs).
- ti-api reading KV ingest overrides; source, pattern or parser changes; migrations; the template build.

## Acceptance criteria

1. `pnpm build` passes; `pnpm test:workers` passes with the tests in section 5.
2. `git diff --name-only main` lists only files under `e2b/`, `apps/collector/`,
   `apps/api/src/routes/internal-jobs.ts`, `apps/api/src/lib/e2b.ts`, `apps/api/test/internal-jobs*` and
   `pnpm-lock.yaml` (only the `e2b/jobs` importer changed).
3. Bench output before and after, saved, with wall time and calls per route at 150 ms latency; after < 120 s.
4. `rg -n "NotImplementedError" e2b/jobs/src/jobs/big-file.ts` finds nothing; `ENABLED_JOB_KINDS` has `big-file`.
5. Saved test output for one changelist first load (red-hat fixtures) and one archive first load (avid files),
   with document, record and inbox row counts.
6. If the loop fetched any real sample (a small `changes.csv` or archive), the PR names the URL and the date;
   otherwise it says every input was hand-built.
7. Proof from `wrangler dev --test-scheduled --port 8700` on the collector (test config, staging env) with a fake
   `API` binding or a stub worker: trigger `30+2+*+*+*` twice and `45+14+*+*+*`, show the logged job ids, the same
   ids the second time, and the signed requests reaching the stub.
8. The PR says what is left: staging timing of KEV after merge, history beyond 10,000 changes, deletions from
   archives, and retrying failed daily starts.
