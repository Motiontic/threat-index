# e2b-heavy-jobs: sandbox data routes, first-load, epss-diff and nightly-fold jobs, and an ops starter

## Why

The E2B bridge works for the `echo` job only. Sandboxes can upload only through presigned R2 URLs, and no
R2 access keys exist, so on staging a sandbox can neither write nor read data. The heavy jobs are stubs
that throw `NotImplementedError`. This change builds `docs/IMPLEMENTATION_PLAN.md` §6 for three jobs:
API routes that let a sandbox read and write R2 and page D1 rows, signed with its per-job key; the
`first-load`, `epss-diff` and `nightly-fold` jobs; and a script that starts any job on staging.

The search index builds at the same time in its own file (`e2b/jobs/src/jobs/search-index.ts`). This
change enables that kind and gives it the client and write prefixes it needs. It does not write that job.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/internal-jobs.ts` | `POST /internal/jobs` (ops key), `GET /internal/jobs/:id`, `POST …/upload-urls` (presigned PUTs, `503 r2_not_configured` without R2 keys), `POST …/complete`. Bodies ≤ 16 KiB. `jobAuth` verifies with `deriveJobKey(JOB_HMAC_SECRET, id)` over `pathname` only. The start schema needs `sourceId` for every kind except `echo` |
| `apps/api/src/lib/e2b.ts` | `ApiJobKind = JobRequest['kind'] \| 'echo'`; `ENABLED_JOB_KINDS = ['echo']`; `SandboxJob { id, kind, sourceId?, url?, apiBase, hmac }` |
| `apps/api/src/lib/presign.ts` | `allowedPrefixes(kind, jobId)` → `jobs/<id>/`, `inbox/<id>/`; `uploadKeyError` (charset, `..`, bare prefix, reserved `request.json`) |
| `apps/api/src/lib/env.ts` | `Bindings` has no `DB_SIGNALS` (the Wrangler config binds it); `@ti/db` `databasesFromEnv` maps every bound D1 |
| `e2b/jobs/src` | `client.ts` (`uploadUrls`, `upload` via presigned URLs, `complete`), `run.ts`, `round-trip.ts` (echo only), `jobs/*.ts` stubs; depends on `@ti/core`, `@ti/parsers` only |
| `e2b/e2b.Dockerfile` | Node 22 bookworm-slim, DuckDB CLI 2.0.1 (pinned and checksummed), `jobs/dist/` copied to `/app` |
| Sources | `cisa-kev` has `parser: 'kev'` (the only real parser) but no `pull` or `urls`; `epss` is `heavy`, licence `ask`, no pull config; the `cve-json5` parser is a stub |
| D1 | `vulns` has `epss`, `epss_pct`, `epss_date`, `epss_model`, but its write rule is `newer` on `modified`, so a row that only changes EPSS is dropped by the loader. `changes` is `insert-ignore` |
| `@ti/core/r2-keys` | `lakeKey(table, sourceId, year, part)` → `lake/<table>/<source>/<year>/part-<part>.parquet` (from the shared seams) |
| EPSS feed | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (FIRST's data page, Nov 2026). It redirects, so follow redirects. The file is gzipped CSV: a `#model_version:…,score_date:…` comment line, then the `cve,epss,percentile` header |

## What to build

Touch only `e2b/**`, `apps/api/src/routes/internal-jobs.ts`, `apps/api/src/lib/{e2b,presign}.ts`,
`apps/api/vitest.workers.mts`, a new `apps/api/test/internal-jobs-data.workers.test.ts`, new
`fixtures/epss/` files and `pnpm-lock.yaml` (see section 5 for the only lockfile change allowed). Don't edit migrations,
`apps/api/src/index.ts`, `env.ts`, `packages/**` or other apps.

### 1. Job kinds and start (`e2b.ts`, `internal-jobs.ts`)

- `export const SOURCE_JOB_KINDS = ['first-load', 'epss-diff', 'big-file'] as const` (= `JobRequest['kind']`)
  and `export const GLOBAL_JOB_KINDS = ['nightly-fold', 'search-index'] as const`.
  `ApiJobKind = JobRequest['kind'] | (typeof GLOBAL_JOB_KINDS)[number] | 'echo'`.
  `@ti/core/control` is left alone: the collector never starts a global job.
- `ENABLED_JOB_KINDS = ['echo', 'first-load', 'epss-diff', 'nightly-fold', 'search-index']`.
- The start schema gains `{ kind: 'nightly-fold' | 'search-index', reason, requestId?, day? }`: no source,
  `requestId` matches `JOB_ID` (else `newJobId`), `day` is `YYYY-MM-DD`. One active job per kind still holds
  (`source_id IS NULL`). `SandboxJob` and `Job` (`e2b/jobs/src/types.ts`) gain `day?: string`.

### 2. Data routes (`internal-jobs.ts`, `presign.ts`)

All four routes use the sandbox key (`deriveJobKey(JOB_HMAC_SECRET, id)`), need a job row with status
`running` (`409 job_not_running`) and log only the job id, route, key or table, and status.

- **Signed path.** For these routes the signed `path` is `pathname + search` exactly as received, so the
  query is covered. GETs sign the empty body. Reject any raw path containing `%` (`400 invalid_key`).
- **`PUT /internal/jobs/:id/objects/<key>`.** The headers are `content-length` (`411 length_required` if
  missing), `x-ti-content-sha256` (64 lowercase hex characters) and `content-type`. The signed body string is
  that digest. The handler reads no body bytes into memory or into a hash. Over `MAX_OBJECT_BYTES = 50 MiB` →
  `413 body_too_large` before reading. It streams `c.req.raw.body` to `BUCKET.put(key, body, { sha256,
  httpMetadata: { contentType } })`, so R2 checks the digest. A mismatch → `400 checksum_mismatch`, and nothing is
  stored. A content type not matching `^[a-z0-9.+-]+/[a-z0-9.+-]+$` is stored as `application/octet-stream`.
  Answers `{ key, size }`. The Workers free plan allows 10 ms of CPU, which rules out hashing in the Worker.
- **Write rules** (`presign.ts`): `allowedPrefixes(kind, jobId, sourceId: string | null): string[]` is
  `jobs/<id>/` and `inbox/<id>/` for every kind, plus `lake/records/<sourceId>/` for `first-load`,
  `lake/epss/epss/` for `epss-diff`, `lake/raw/` for `nightly-fold`, and `lookup/search/`, `lookup/index/`,
  `lookup/vuln/`, `lookup/pkg/` for `search-index`. `ALLOWED_EXACT_KEYS: Partial<Record<ApiJobKind,
  string[]>> = { 'search-index': ['sitemap.xml'] }`. `uploadKeyError(key, prefixes, exact = [])` accepts an
  exact key and keeps every current rule. `upload-urls` uses the same rules.
- **`GET /internal/jobs/:id/objects/<key>`** streams the object (`content-type` and `content-length` set)
  when the key is under `readPrefixes(jobId)` = `raw/`, `lake/`, `lookup/`, `jobs/<id>/`, `inbox/<id>/`
  (`readKeyError(key, prefixes)`: same charset and segment rules), else `400 invalid_key`. Missing → `404`.
- **`GET /internal/jobs/:id/list?prefix=<p>&cursor=<c>`.** `p` must be non-empty and inside a read prefix
  (a read prefix itself is allowed). Answers `{ objects: { key, size }[], cursor: string | null }`, at most 1,000
  per page, from `BUCKET.list({ prefix, cursor, limit: 1000 })`.
- **`GET /internal/jobs/:id/rows/<table>?after=<cursor>&limit=<n>`.** `table` ∈ `ROW_TABLES = ['vulns',
  'advisories', 'signals']`, with primary keys `[key]`, `[source, source_id]` and `[vuln_key, kind, source,
  ref]`, hard-coded and never taken from input. `limit` is 1–1,000 (default 500). `after` is the
  base64url JSON array of the last row's key values. Query: `SELECT * FROM <t> WHERE (<pk>) > (?…) ORDER BY <pk>
  LIMIT ?` (no `WHERE` without `after`), on `databasesFromEnv(c.env)[databaseFor(table)]`. Answers
  `{ rows, next }`, where `next` is null when fewer than `limit` rows came back. A bad table, limit or cursor
  → `400 invalid_query`. `echo` jobs get `403 not_allowed`.

### 3. Sandbox client (`e2b/jobs/src/client.ts`)

`JobApi` keeps `uploadUrls` (the presigned path, for when R2 signing is configured) and `complete`, and gains:

```ts
export const MAX_OBJECT_BYTES = 50 * 1024 * 1024;
export type RowTable = 'vulns' | 'advisories' | 'signals';
putObject(key: string, body: Uint8Array | string, contentType: string): Promise<void>;
getObject(key: string): Promise<Uint8Array | null>;            // 404 → null
list(prefix: string): AsyncIterable<{ key: string; size: number }>;
rows(table: RowTable, opts?: { after?: string; limit?: number }): Promise<{ rows: Record<string, unknown>[]; next: string | null }>;
allRows(table: RowTable): AsyncIterable<Record<string, unknown>>; // pages of 500
```

`upload(files)` now calls `putObject` for each file, so `echo` works without R2 keys. Every call is signed as in section 2 and
retried 3 times on a network error or 5xx, as today. A body over `MAX_OBJECT_BYTES` throws before sending. Error messages
carry the route and status, never a URL query, the key or a body.

### 4. Jobs (`e2b/jobs/src/jobs/*.ts`, shared helpers in `e2b/jobs/src/lib/`)

- **`lib/ulid.ts`:** `newUlid(now?)` and `deterministicUlid(timeMs, seed)` (randomness = the first 80 bits of
  SHA-256(seed), Crockford base32).
- **`lib/download.ts`:** `download(url, dest, deps)` accepts `https:` only, follows ≤ 5 redirects (each
  `https:`), caps the size at 1 GiB, sends `User-Agent: ThreatIndex-jobs (+<repo URL>)`, retries 3 times on a
  network error or 5xx, and gunzips when the URL path ends `.gz`.
- **`lib/lake.ts`:** `writeLakePart(rows, columns: Record<string, 'VARCHAR' | 'DOUBLE' | 'BIGINT'>, deps)`
  returns `{ bytes, format: 'parquet' | 'ndjson.gz' }`. With `duckdb` on `PATH` it writes NDJSON to a temp
  dir and runs `duckdb -c "COPY (SELECT * FROM read_json('<in>', format='newline_delimited', columns={…})) TO
  '<out>' (FORMAT parquet, COMPRESSION zstd)"` through `execFile` with an empty environment. Temp names come
  from the job id, never from data. Without it, it writes gzipped NDJSON. `lakeObjectKey(table, source, year,
  part, format)` is `lakeKey(...)`, or the same key with `.ndjson.gz` in place of `.parquet`.
  `readLakePart(bytes, format)` reverses it (DuckDB `read_parquet` → NDJSON). Every job logs `format`. A part
  over `MAX_OBJECT_BYTES` fails the job with a clear message: splitting parts comes later.
- **`lib/inbox.ts`:** `writeInbox(api, jobId, rows: InboxRow[])` writes gzipped NDJSON chunks of
  `MAX_ROWS_PER_CHUNK` at `inboxChunkKey(jobId, n)`, then `inboxManifestKey` (`{ jobId, createdAt, chunks }`)
  last. It writes an empty manifest when there are no rows, because `complete` requires one.
- **`first-load`** (`job.sourceId` required): source from `SOURCE_BY_ID` (`@ti/sources/registry`). No `parser`
  → fail `source <id> has no parser`. URL: `job.url`, else `pull.heavy.url`, `pull.fingerprint.url`,
  `urls[0]`; none → fail. Download, then parse: `JSON.parse` when the path ends `.json`/`.json.gz` or the
  content type is JSON, else the text. `loadParser(source.parser)`, accept `ParsedRecord[]` or `ParseResult`.
  Link in batches of 5,000 records with `LinkDeps`: `read(table, keys)` serves `ROW_TABLES` from a cache filled
  once per table with `allRows`, and returns `[]` for other tables. After each batch the batch's upserts are
  merged into the cache so the next batch sees them. `lookupCold` reads `lookupVulnKey(key)` through
  `getObject`, caches each shard and returns `null` when the shard or key is missing. `now`, `newId` = `newUlid`.
  Lake: records as `{ source, job_id, n, record }` (`record` = JSON text) at
  `lake/records/<source>/<yyyy>/part-<jobId>.<ext>`. Then `writeInbox`. Log counts and `docs.length` only.
  KEV is the worked source. Its source file has no URL on main, so the ops script passes `--url`.
- **`epss-diff`** (`sourceId` `epss`): download the EPSS URL above (`job.url` overrides it). Parse the
  comment line (`model_version`, `score_date` → day) and the CSV in Node. Rows that don't parse are counted;
  more than 1% bad rows fails the job. Write `{ cve, epss, percentile, model_version, score_date }` to
  `lake/epss/epss/<yyyy>/part-<day>.<ext>`, which overwrites on a rerun. Read the part for day − 1 (either format).
  Missing → no changes, logged `no previous day`. Hot keys = `allRows('vulns')` with `hot = 1`. For each
  hot CVE in both days where `epssBand` (`@ti/linker/detect`) differs, emit `{ table: 'changes', op: 'upsert',
  row: { id: deterministicUlid(dayMidnightMs, 'epss_band:<cve>:<day>'), entity_key, kind: 'epss_band', old,
  new, at: <day>T00:00:00Z, source: 'epss' } }`. Over 50,000 changes fails the job. Then `writeInbox`.
  **`vulns.epss*` are not updated in D1:** the loader's `newer` rule drops a row whose `modified` did not
  advance. The scores live in `lake/` only, and the PR says so.
- **`nightly-fold`:** day = `job.day` or yesterday (UTC). For each registry source with
  `canIngest(licence)`, `list('raw/<id>/<yyyy>/<mm>/<dd>/')`, download each `.ndjson.gz`, and gunzip and split its
  lines into `{ source, run_id, step, type, item_id, fetched_at, content_type, encoding, body }`. `run_id`
  and `step` come from the file name `<runId>-<step>`. Unparseable lines are counted and skipped. Write one
  part per source with receipts at `lake/raw/<id>/<yyyy>/part-<day>.<ext>` (rerun overwrites), then an
  empty inbox manifest.
- `run.ts` deletes `JOB_JSON` as today. DuckDB child processes get no environment.

### 5. Packaging, template and ops script

- `e2b/jobs/package.json` adds `"@ti/linker": "workspace:*"` and `"@ti/sources": "workspace:*"` (no external
  package). `pnpm install` may change only the `e2b/jobs` importer block of `pnpm-lock.yaml`.
- `build.mjs` keeps `target: 'node22'`. The bundle must contain every parser that `loadParser` can load:
  check `grep -c parseKev dist/run.mjs`.
- `e2b.Dockerfile` already installs Node 22, DuckDB 2.0.1 and the bundle. Add `RUN duckdb --version` and
  `ENV NODE_OPTIONS=--max-old-space-size=3072`, and leave the rest alone. `build-template.mjs` is unchanged
  (2 vCPU / 4 GB).
- **`e2b/jobs/src/start-job.ts`** (`"start-job"` script): `JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs
  start-job -- --api <origin> --kind <kind> [--source <id>] [--url <https>] [--day YYYY-MM-DD] [--no-wait]`.
  It makes a ULID `requestId`, signs `POST /internal/jobs`, then polls `GET /internal/jobs/:id` like
  `round-trip.ts`, which now shares its `signedSend` and `pollJob`. It prints the job id and status only, and
  exits 0 only on `complete`. Update `e2b/README.md` with the staging commands. KEV:
  `--kind first-load --source cisa-kev --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
  No cron starts these jobs: that needs a collector change, which comes later.

### 6. Tests (fixtures only; no test touches the network or needs DuckDB)

- **Workers** (`internal-jobs-data.workers.test.ts`, seeded `jobs` rows): PUT stores bytes and content type;
  a wrong signature, another job's key, or a changed query → 401. A digest that doesn't match the body →
  `checksum_mismatch` and no object. Outside prefixes, `jobs/<id>/request.json`, `..` or `%2e` → 400. `lake/records/<other
  source>/` → 400 for first-load. `sitemap.xml` is OK for search-index only. No content-length → 411; a declared
  51 MiB → 413; a job not running → 409. GET: own inbox and `raw/` OK, another job's `jobs/` 400, missing 404.
  list: pages with a cursor, outside prefix 400. rows: 3 vulns at `limit=2` → 2 + `next`, then 1 + `null`;
  composite-key paging on `advisories` and `signals`; `users` or `limit=1001` → 400; echo → 403. Start:
  `nightly-fold` with no source → 201 with `day` passed to the fake launcher; a second one → `existing`.
- **Node** (`e2b/jobs/src/*.test.ts`): the client (signature verifies with `verifyRequest`, the digest header,
  404 → null, rows and list paging, 5xx retry). `deterministicUlid` is stable. The lake NDJSON path round-trips,
  and with a fake `execFile` the DuckDB command has no data-derived names. `first-load` on
  `fixtures/cisa-kev/sample.json` with a fake API and fetch writes chunks of ≤ 500, the manifest last and a lake
  part, and fails on no parser or no URL. `epss-diff` on new `fixtures/epss/{today,yesterday}.csv` (hand-written,
  10 rows each, real format) emits only hot band changes with stable ids, and finds no previous day.
  `nightly-fold` folds two fake receipts and skips a bad line. `start-job` sends a signed request that verifies.

## Not in scope

- `search-index` job logic (its own feature); `big-file`, `compaction` and `deep-query`; `lookup/` shards from
  the first load; Parquet part splitting; compaction.
- CVE List's first load (a large zip of per-record files) and any per-source download quirk beyond KEV.
- Writing EPSS into `vulns` in D1 (it needs a loader rule for column-only updates); the source files' pull configs.
- Cron wiring for the nightly jobs, a template with 8 vCPU, migrations, and a read-only R2 token for DuckDB.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass with the tests in section 6.
2. `git diff --name-only main` lists only the paths allowed in "What to build", and `git diff main --
   pnpm-lock.yaml` touches only the `e2b/jobs` importer.
3. `rg -n "NotImplementedError" e2b/jobs/src/jobs/{first-load,epss-diff,nightly-fold}.ts` finds nothing.
4. `pnpm --filter @ti/e2b-jobs bundle` succeeds, and `grep -c parseKev e2b/jobs/dist/run.mjs` is ≥ 1. Save
   the output and the bundle size.
5. Local proof, output saved. Write `apps/api/wrangler.test.jsonc` (`writeTestConfig`). Apply the control,
   vulns, advisories and signals migrations `--local --env staging`, then run `wrangler dev --env staging --port 8700
   --var JOB_HMAC_SECRET:<dummy> --var API_BASE:http://localhost:8700`. Insert a `running` `first-load` job
   row for `cisa-kev` with `wrangler d1 execute --local`. Run `pnpm --filter @ti/e2b-jobs job` with that id,
   `apiBase` `http://localhost:8700`, `hmac` from `deriveJobKey`, and the KEV feed URL (fetched live; say
   so). If the live fetch fails, say so and point to the Node test instead; `download` never takes a non-HTTPS
   URL just for the proof. Show the job ending `complete`, the keys under `inbox/<id>/` and
   `lake/records/cisa-kev/` (through the signed `list` route; `wrangler r2 object get --local` for the manifest), and the queued `ti-load` messages in the dev log. Say whether
   the lake part was Parquet (DuckDB fetched from the Dockerfile's pinned URL and checksum) or NDJSON.gz.
6. The same for `nightly-fold`: put one receipt under `raw/cisa-kev/<yesterday>/` with `wrangler r2 object
   put --local`, run the job, and list `lake/raw/cisa-kev/` the same way. Stop the server.
7. The PR states each platform fact it relies on, with a docs link: R2 `put` with `sha256` and a streamed
   request body of known length (locally too), the Workers request body limit, the free plan's CPU limit,
   EPSS's URL and file format, DuckDB `read_json` `columns` and `COPY … FORMAT parquet`, and esbuild's
   template-literal dynamic import. It also says that no E2B or staging run was possible and gives the
   `start-job` commands for one.

## Coordination with work built at the same time

- Pass the public site origin to every sandbox as `SITE_ORIGIN` (from a new optional ti-api var, filled from
  `TI_APP_URL_STAGING` / `TI_APP_URL` by the existing placeholders), so the search-index job can write absolute
  sitemap URLs. Unset → not passed.
- The search-index job is built at the same time with its own minimal client. Keep the signing rule simple for
  it: the signed path for a GET is `pathname + search` exactly as sent; document it in `e2b/README.md`.
- The account is on Workers Paid, so CPU per request is not limited to 10 ms; still stream bodies and keep the
  rows route default page at 500.
