# deep-query: full-history questions answered from the data lake by allow-listed DuckDB templates

## Why

The API answers from D1 and the `lookup/` shards, which hold only hot rows. The full history lives in `lake/`:
every first-loaded record, every day of EPSS and every receipt. `POST /v1/deep-query` and
`GET /v1/deep-query/:id` are stubs that answer 501. This change builds `docs/IMPLEMENTATION_PLAN.md` §6
`deep-query:<id>` and §8: a signed-in user picks one of five query templates and fills in typed parameters,
the API starts a short E2B job, the job runs DuckDB over `lake/` parts and writes a JSON result, and the user
polls for it. Users never send SQL, and no user text is ever placed in SQL.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/deep-query.ts` | `POST /v1/deep-query` and `GET /v1/deep-query/:id`, both `requireUser` then `notImplemented` |
| `apps/api/src/lib/e2b.ts` | `JobLauncher` (`create({ timeoutMs, metadata })` → `{ sandboxId, start(job) }`, `kill`), `launcherFromEnv`, `parseApiBase`, `newJobId`, `describeE2bError`, `MAX_ACTIVE_JOBS = 5`, `ApiJobKind = JobRequest['kind'] \| GlobalJobKind \| 'echo'`, `ENABLED_JOB_KINDS` (no `deep-query`) |
| `apps/api/src/routes/internal-jobs.ts` | Ops start (its schema has no `deep-query`), status, and the sandbox routes signed with `deriveJobKey(JOB_HMAC_SECRET, id)`: `PUT/GET …/objects/<key>`, `GET …/list?prefix=`, `GET …/rows/<table>`, `POST …/complete`. `complete` with `ok: true` requires `inbox/<id>/manifest.json` (an empty one is fine), sets `complete`, kills the sandbox |
| `apps/api/src/lib/presign.ts` | Every kind may write under `jobs/<id>/` and `inbox/<id>/` (not `jobs/<id>/request.json`); every job may read `raw/`, `lake/`, `lookup/` and its own `jobs/<id>/` |
| `ti_control.jobs` | `id, kind, source_id, status, sandbox_id, created_at, finished_at, manifest_key, error`. No user column, no KV binding; migrations are not edited here |
| `e2b/jobs/src` | `client.ts` (`getObject`, `list`, `putObject`, `complete`), `lib/lake.ts` (`findDuckdb`, `readLakePart`, `ExecFile`, `LakeDeps`), `lib/inbox.ts` (`writeInbox`), `lib/work.ts` (`withScratch`, `YMD`, `dayStartMs`), `test-support.ts` (`fakeApi`, `fakeCtx`, `job`, `gz`); `run.ts` maps `deep-query` to `jobs/deep-query.ts`, which throws `NotImplementedError` |
| Lake layout | `lake/records/<source>/<yyyy>/part-<jobId>.{parquet,ndjson.gz}`: columns `source, job_id, n, record` (`record` = one `ParsedRecord` as JSON text), one part per first-load job, so reruns repeat records. `lake/epss/epss/<yyyy>/part-<day>.{…}`: `cve, epss, percentile, model_version, score_date` |
| Auth in tests | `vi.mock('@hono/clerk-auth')` does not work in the Workers pool; `account.workers.test.ts` mounts routes on a test app whose middleware sets `clerkAuth` from a header |

This change needs the sandbox data routes above. If `GET /internal/jobs/:id/objects/<key>` is missing on
main, stop and say so.

## What to build

Touch only `apps/api/src/routes/deep-query.ts`, new `apps/api/src/lib/deep-*.ts`, two lines of
`apps/api/src/lib/e2b.ts` (add `'deep-query'` to the `ApiJobKind` union and to `ENABLED_JOB_KINDS`; the union
edit is needed for the list to type-check), new `apps/api/test/deep-query.workers.test.ts`,
`e2b/jobs/src/jobs/deep-query.ts` and new `e2b/jobs/src/jobs/deep-query*.test.ts`. No migrations, no
`index.ts`, no `packages/**`, no new fixture directory.

### 1. Templates and parameters (`apps/api/src/lib/deep-templates.ts`)

This file has **no imports**, so both the Worker and the sandbox use it (the sandbox imports it by relative
path with a `.ts` extension; it moves to `@ti/core` later). It exports:

```ts
export type DeepTemplate = 'cve-history' | 'package-advisories' | 'epss-history' | 'company-breaches' | 'kev-additions';
export type ParamType = 'cve' | 'ecosystem' | 'package' | 'company' | 'day';
export interface DeepQuery { template: DeepTemplate; params: Record<string, string> }
export const DEEP_TEMPLATES: Record<DeepTemplate, { params: Record<string, ParamType>; optional?: string[] }>;
export function validateDeepQuery(input: unknown): { ok: true; query: DeepQuery } | { ok: false; field: string };
export const MAX_RESULT_ROWS = 1000;
export const MAX_SPAN_DAYS: Partial<Record<DeepTemplate, number>> = { 'epss-history': 31, 'kev-additions': 366 };
```

| Template | Params | Answers |
| -------- | ------ | ------- |
| `cve-history` | `cve` | Every record from every source whose `key`, `vulnKey` or `aliases` is the CVE, each distinct version once |
| `package-advisories` | `ecosystem`, `package` | Advisory records with an `affected` entry for that ecosystem (case-insensitive) and exact package name |
| `epss-history` | `cve`, `from`, `to` | One row per day: `day, epss, percentile, model` |
| `company-breaches` | `company` | Notice records whose `companyKey` equals a `cik:`/`domain:` key, or whose `rawName` contains the name (case-insensitive) |
| `kev-additions` | `from`, `to` | `cisa-kev` `exploited_wild` signals with `firstSeen` in the range, latest version per CVE |

Parameter types, each a strict whole-string regex; anything else is refused, never escaped:
`cve` `^CVE-\d{4}-\d{4,7}$` (input is upper-cased first); `ecosystem` `^[A-Za-z][A-Za-z0-9 .:_-]{0,39}$`;
`package` `^[A-Za-z0-9@/._+:-]{1,214}$`; `company` is `cik:\d{1,10}`, `domain:` plus a lower-case host
(`^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$`, ≤ 253 chars), or a name `^[\p{L}\p{N} .,&'()-]{2,80}$` (`u` flag,
trimmed); `from`/`to` are real `YYYY-MM-DD` days, `from ≤ to`, `to` not after today (UTC), span ≤ `MAX_SPAN_DAYS`.
`to` defaults to today and `from` to `to − (span − 1)` where a template allows it. The body is exactly
`{ template, params }`; an unknown template, a missing or extra param, or a non-string value fails with that
`field` name.

### 2. API route (`apps/api/src/routes/deep-query.ts`, `apps/api/src/lib/deep-query.ts`)

`export function createDeepQueryRoute(deps: { launcher?, now?, newId? } = {})` (same shapes as
`InternalJobsDeps`); the default export is `createDeepQueryRoute()`. Both routes keep `requireUser`, send
`cache-control: no-store`, and log only the job id, template, status and sandbox id: never the user id or params.

- **Owner.** `deepOwner(secret, userId)` = `'dq:' + hmacHex(JOB_HMAC_SECRET, 'deep-query-owner:' + userId).slice(0, 32)`
  (`hmacHex` from `lib/auth.ts`), stored in `jobs.source_id`. No Clerk id is written to D1 or R2. No secret →
  `503 e2b_not_configured`.
- **Limits** (`lib/deep-query.ts`): `DEEP_RATE_PER_HOUR = 10` per owner, counted from `jobs` rows of kind
  `deep-query` with `created_at` in the last hour (failed ones count); `MAX_ACTIVE_DEEP = 3` across all users, so
  heavy jobs keep two of the `MAX_ACTIVE_JOBS` slots; one active query per owner; `DEEP_QUERY_TIMEOUT_MS = 5 min`
  (sandbox timeout); `DEEP_QUERY_STALE_MS = 6 min`.
- **`POST /v1/deep-query`.** Body ≤ 2 KiB (`413 body_too_large`), JSON (`400 invalid_body`),
  `validateDeepQuery` (`400 invalid_query` with `{ field }`). `deep-query` not in `ENABLED_JOB_KINDS` → `501`.
  No launcher or `parseApiBase(API_BASE)` null → `503 e2b_not_configured`. Then:
  1. Mark this owner's `starting`/`running` deep-query rows older than `DEEP_QUERY_STALE_MS` as `timed_out`
     and kill their sandboxes after the response (`waitUntil`, errors logged with `describeE2bError`).
  2. One `INSERT … SELECT … WHERE` adds the row as `starting` only if the owner has no active query, made
     fewer than 10 in the last hour, fewer than `MAX_ACTIVE_DEEP` deep queries are active and fewer than
     `MAX_ACTIVE_JOBS` jobs are active. On no insert, answer in this order: active query → `409 query_running`
     `{ id }`; rate → `429 rate_limited` with `retry-after` (seconds until the oldest counted row is an hour
     old); else `503 busy`.
  3. Put `jobs/<id>/request.json` = `{ kind: 'deep-query', template, params, createdAt }`.
  4. `launcher.create({ timeoutMs: DEEP_QUERY_TIMEOUT_MS, metadata: { jobId, kind: 'deep-query' } })`, set
     `running` + `sandbox_id`, `start({ id, kind: 'deep-query', apiBase, hmac: deriveJobKey(…) })`. Any failure
     marks the row `failed` and answers `502 launch_failed` (kill the sandbox if one was made).
  5. `202 { id, status: 'running' }`.
- **`GET /v1/deep-query/:id`.** `id` must match the job-id shape. A row that is missing, not `deep-query`, or
  owned by someone else → `404 not_found` (same body). Run the stale sweep for this owner first. Answer
  `DeepQueryStatus`:

```ts
export interface DeepQueryStatus {
  id: string; template: DeepTemplate; params: Record<string, string>;
  status: 'running' | 'complete' | 'failed'; createdAt: string; finishedAt: string | null;
  error?: 'invalid_params' | 'scan_too_large' | 'query_failed' | 'timed_out' | 'result_missing';
  result?: DeepQueryResult; credits?: Credit[];
}
export interface DeepQueryResult {
  template: DeepTemplate; rows: Record<string, unknown>[]; rowCount: number; truncated: boolean;
  sources: string[]; scanned: { objects: number; bytes: number }; tookMs: number;
}
```

  `starting`/`running` → `running`; `timed_out` → `failed` + `timed_out`. For `failed`, `jobs.error` of the form
  `deep-query: <code>` with a listed code passes through, anything else becomes `query_failed`; the raw error is
  never shown. For `complete`, read `jobs/<id>/result.json` (≤ 5 MiB; missing, larger or not JSON → `failed` +
  `result_missing`) and add `credits = searchCredits([result.sources])`.

### 3. Sandbox job (`e2b/jobs/src/jobs/deep-query.ts`)

`export const run: RunJob`, plus exported pure helpers the tests use: `planScan`, `buildSql`, `matches`,
`finish`. Steps:

1. `getObject('jobs/<id>/request.json')`; missing or failing `validateDeepQuery` → throw
   `deep-query: invalid_params`. The sandbox validates again; it never trusts the API's copy.
2. **Plan** (`planScan(query, objects)`): list prefixes from the template only. `cve-history`,
   `package-advisories`, `company-breaches`: `lake/records/<id>/` for each registry source with
   `canIngest(licence)`. `kev-additions`: `lake/records/cisa-kev/`. `epss-history`: `lake/epss/epss/<yyyy>/` for
   the years in range, keeping parts named `part-<day>` inside it. Keep keys ending `.parquet` or `.ndjson.gz`.
   Over `MAX_SCAN_OBJECTS = 2000` or `MAX_SCAN_BYTES = 512 MiB` → throw `deep-query: scan_too_large` before
   downloading anything.
3. **Fetch** with `getObject`, 8 at a time, into `withScratch(job.id, …)` as `p-<n>.parquet` /
   `p-<n>.ndjson.gz`. File names come from the index, never from a key or a param.
4. **Query.** With DuckDB (`findDuckdb()`, or `deps.duckdb`): write the params to `params.json` in the scratch
   dir and run `buildSql(template, files, dir)` via `execFile(duckdb, ['-c', sql], { env: {}, timeout: 120 s })`.
   The SQL is a constant per template plus a `parts` view over the generated file names
   (`read_parquet([…], union_by_name=true)` and/or `read_json([…], format='newline_delimited', columns={…})`) and
   `p AS (SELECT * FROM read_json('<dir>/params.json'))`. Parameters reach DuckDB only through that file, so no
   param text is ever in the SQL. The SQL narrows rows (e.g. `contains(record, p.cve)` and a record-shape check),
   adds `LIMIT 5000`, and `COPY`s to `<dir>/out.ndjson`. Without DuckDB, `.ndjson.gz` parts are read in Node and a
   Parquet part fails the job with `deep-query: query_failed` (log `duckdb missing`).
5. **Finish** in Node (`finish`): parse each `record`, keep rows where `matches(query, row)` holds (the exact
   rule from section 1, so the SQL can only narrow, never widen), drop exact duplicates
   (`source` + record text), keep the newest `job_id` per record identity for every template but
   `cve-history`, sort (by `source` then `modified`/`firstSeen`/`day`), and cap at `MAX_RESULT_ROWS`
   (`truncated`). Records rows are `{ source, jobId, record }`; EPSS rows are `{ day, epss, percentile, model }`.
   If the JSON is over 5 MiB, drop rows from the end and set `truncated`.
6. `putObject('jobs/<id>/result.json', …, 'application/json')`, then `writeInbox(api, id, [])` (an empty manifest,
   because `complete` requires one). `run.ts` then sends `complete({ ok: true })`. Log counts, bytes and
   per-phase milliseconds (`list`, `fetch`, `query`) only.

### 4. Tests

- **Workers** (`deep-query.workers.test.ts`, the test-app auth stub, a fake launcher recording `create`/`start`/
  `kill`, seeded `jobs`): signed out → 401; a bad template, extra param, `cve` `CVE-1' OR 1=1` and a 3 KiB body
  → 400/413; POST → 202, row `running` with `source_id` starting `dq:` and not containing the user id,
  `request.json` without the user id, `start` got `kind: 'deep-query'` and no params; a second POST → 409; the
  11th in an hour → 429 with `retry-after`; 3 active deep queries → 503 `busy`; launcher throws → 502 and row
  `failed`; a 7-minute-old running row is swept to `timed_out` and its sandbox killed. GET: other user's id →
  404; running; complete with a stored `result.json` → rows and credits; failed with raw error text → only
  `query_failed`; complete with no result → `result_missing`.
- **Node** (`deep-query*.test.ts`, no network, no DuckDB): every template accepts a good example and rejects
  bad ones (quotes, `;`, `--`, newline, over-long, unknown key, span over the limit, `to` in the future);
  `buildSql` output contains no param value for a set of values and is identical for two different params;
  `params.json` holds them; with a fake `execFile` the argv is `['-c', sql]` and `env` is `{}`; `planScan` skips
  `link`/`wait` sources and fails `scan_too_large`. End-to-end with `fakeApi`: lake parts built in the test as
  `.ndjson.gz` (KEV records from `parseKev` on `fixtures/cisa-kev/sample.json`, two copies under two job ids, plus
  inline advisory, notice and vuln records, and EPSS rows from `fixtures/epss/*.csv`) give the right rows for each
  template, dedupe the KEV copies, write `result.json` and an empty manifest; a missing `request.json` fails.

## Not in scope

- Any template beyond these five, free-form filters, paging through results, and the web page for this.
- A read-only R2 token so DuckDB reads `lake/` directly with range requests, and partitioning or compaction so
  `cve-history` need not scan every records part. Until then `scan_too_large` is the honest answer for a big lake.
- Deleting `jobs/<id>/` results (a lifecycle rule) and removing a user's deep-query rows on account deletion.
- A staging measurement of the < 30 s target: there are no E2B or staging credentials in this build.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass with the tests in section 4; `pnpm typecheck` passes repo-wide.
2. `git diff --name-only main` lists only the paths allowed in "What to build"; `git diff main -- apps/api/src/lib/e2b.ts`
   is two changed lines.
3. `rg -n "NotImplementedError|notImplemented" e2b/jobs/src/jobs/deep-query.ts apps/api/src/routes/deep-query.ts`
   finds nothing, and `rg -n "\\$\\{.*param" e2b/jobs/src/jobs/deep-query.ts` finds no param interpolated into SQL.
   Save both outputs.
4. `pnpm --filter @ti/e2b-jobs bundle` succeeds and the bundle contains `cve-history`. Save its size.
5. Local proof, output saved: `wrangler dev --env staging --port 8700 --var JOB_HMAC_SECRET:<dummy> --var
   API_BASE:http://localhost:8700` with the control migration applied `--local`; insert a `running` `deep-query`
   row, put its `request.json` (`kev-additions` for a range in the KEV sample) and one `.ndjson.gz` KEV part
   under `lake/records/cisa-kev/` with `wrangler r2 object put --local`; run `pnpm --filter @ti/e2b-jobs job`
   with that id and `deriveJobKey`. Show the job ending `complete`, `jobs/<id>/result.json`, and the job's
   per-phase timings. Say whether DuckDB ran (fetched from the Dockerfile's pinned URL and checksum) or the Node
   path did; if DuckDB ran, also run `cve-history` against the same part.
6. The PR states each platform fact it relies on, with a docs link: DuckDB `read_json` / `read_parquet` with a
   file list and `union_by_name`, `json_extract_string`, and `COPY … TO` JSON. It says that no E2B or staging run
   was possible, that < 30 s is unmeasured there, and which scans would exceed the limits today.
