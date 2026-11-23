# collector-runtime: plan due sources, run one step per message, hand off, dead-letter, watchdog

## Why

The collector Worker is wired but does no work. The planner queues every source on every tick under one
timestamp run id, the `ti-jobs` consumer acks each message untouched, and the watchdog is an empty stub.
This change builds `docs/IMPLEMENTATION_PLAN.md` §5, steps 1–8: pick the due sources, run one small step per
queue message, hand big files to E2B through ti-api, record dead-lettered messages and email a daily report.

Other features are built at the same time and fill in what a step calls: the pull patterns
(`packages/patterns/**`), the linker (`packages/linker/**`), the writer and budget (`packages/db/src/**`,
`apps/loader/**`) and ti-api's `POST /internal/jobs` (`apps/api/**`). On `main` they are stubs. The step takes
them as injected dependencies, so its tests use fakes and never rely on a stub's body.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/collector/src/planner.ts` | `CADENCE_BY_CRON`; `dueSources(cron)` filters by cadence and `canIngest(licence)` only (no KV override, no run history); one `Date.now().toString(36)` run id for all sources; `NOTIFY` run-finished on `0 */3 * * *` |
| `step.ts`, `watchdog.ts` | `runStep` acks every message (`TODO(M1)`), retries with `retryDelaySeconds` on a throw. `watchdog()` is empty, marked "UNWIRED STUB" |
| `apps/collector/src/env.ts` | `JobMessage { sourceId, runId, step }`; no `API`, email or secret bindings |
| `apps/collector/wrangler.jsonc` | 4 crons; `ti-jobs` consumer (batch 5, 5 retries, DLQ `ti-jobs-dlq`), nothing consumes the DLQ; `send_email` and `USER_AGENT` hold a literal `<ops-contact>`; `API_BASE` is a literal `https://api.<domain>` no code reads; staging has no email and no service binding |
| `scripts/wrangler-config.mjs` | Throws when any `${VAR}` in the deployed section is unset; no optional values |
| `ti_control` (`0001_init.sql`) | `runs(id, source_id, started_at, finished_at, status, found, written, bytes, error)`, no step column; `cursors(source_id, kind, value, etag, updated_at)`; `jobs`; `budget(day, d1_writes, …, emails_sent)` |
| Shared contract (merged just before this) | `patternFor`, `PatternContext.wait/log/now`, `link()` and `writeRows()` stubs, `databasesFromEnv`, `rawReceiptKey`, `RUN_STATUSES`, `JOB_STATUSES`, `JobRequest`, `signRequest`/`verifyRequest`, `apps/collector/vitest.workers.mts`; `loadParser` in `@ti/parsers/load` |
| Cloudflare docs (Nov 2026) | Queues: `delaySeconds` ≤ 86,400, ≤ 100 retries, `attempts` starts at 1, `batch.queue` names the queue, producer bindings have `metrics()`. `send_email`: `destination_address` limits the binding to one verified address; a raw `EmailMessage` needs `From` and `Message-ID`. `services` and other bindings don't inherit into `env.staging`; a service binding's target must exist before the caller deploys |

## What to build

Touch only `apps/collector/**`, a new `packages/core/src/settings.ts` (+ test), `scripts/wrangler-config.mjs`
and a new `test/wrangler-config.test.ts`. Don't edit migrations, the shared contract files
(`packages/core/src/{inbox,r2-keys,control,sign}.ts`, `packages/patterns/src/{types,by-name}.ts`,
`packages/linker/src/link.ts`, `packages/db/src/write.ts`), `vitest.workers.config.mts`, `scripts/deploy.mjs`
or `pnpm-lock.yaml`. Add no dependency: `ulid` is already a collector dependency. The collector has no `zod`,
so it checks message bodies by hand.

### 1. KV settings format: `packages/core/src/settings.ts`

```ts
export const SOURCE_SETTINGS_PREFIX = 'source:';           // source:<id> → SourceSettings
export const UNKNOWN_FIELDS_PREFIX = 'unknown-fields:';    // unknown-fields:<id> → UnknownFields
export interface SourceSettings { ingest?: boolean; display?: DisplayMode }
export interface UnknownFields { fields: string[]; firstSeen: string; lastSeen: string } // ISO
export function sourceSettingsKey(sourceId: string): string;
export function unknownFieldsKey(sourceId: string): string;
/** Null for a missing, non-JSON or wrongly shaped value. Unknown keys are ignored. */
export function parseSourceSettings(raw: string | null): SourceSettings | null;
/** Bulk KV get, ≤ 100 keys per call. Ids without a valid override are absent from the map. */
export function readSourceSettings(kv: KVNamespace, ids: readonly string[]): Promise<Map<string, SourceSettings>>;
```

Validate with Zod. A malformed override is ignored, so a bad value never switches a `wait` source on. The API
reads `display` later. Node test `settings.test.ts`: valid values; `{"ingest":"false"}`, bad JSON and a bad
`display` → `null`; extra keys ignored; `readSourceSettings` against a fake KV.

### 2. Planner (`planner.ts`) and message (`env.ts`)

- Keep `CADENCE_BY_CRON`; `30 2 * * *` stays empty. `CADENCE_MS`: `3h` and `with-cve-list` 3 h, `daily`
  24 h, `weekly` 7 d, `monthly` 30 d, `quarterly` 91 d. `isDue(cadence, lastSuccess: Date | null, at: Date)`:
  true with no success, or when `at - lastSuccess >= CADENCE_MS[cadence] - 30 min` (cron ticks drift; without
  slack a 3-hourly source runs every other tick).
- `dueSources(env, cron, at): Promise<{ source: SourceConfig; from: Cursor | null }[]>`: cadence in the cron's
  list, `canIngest(licence, override?.ingest)`, and due. A success is a run with status `ok`, `unchanged` or
  `heavy` (use `started_at`). Skip a source whose latest run is still `running` and started less than 2× its
  cadence ago, so two runs never share a cursor. Read runs (last 200 days) and all cursors in one
  `DB_CONTROL.batch()`.
- `plan(event, env, deps: { newId(): string })`: `at` = `event.scheduledTime`; one message per due source,
  `{ sourceId, runId: ulid(), step: 0, from }`, via `sendBatch` in chunks of ≤ 100. `NOTIFY` stays as today.
- `JobMessage { sourceId; runId; step; from: Cursor | null }`: `from` is the cursor the step starts from.
  `parseJobMessage(body: unknown): JobMessage | null` checks a ULID, an integer step `0..500`
  (`MAX_STEPS_PER_RUN`) and a `Cursor` with a known `kind`; today's old-format messages fail it.
- `Env` gains `API?: Fetcher`, `JOB_HMAC_SECRET?`, `OPS_EMAIL?: SendEmail`, `OPS_EMAIL_TO?`, `OPS_EMAIL_FROM?`.
  `USER_AGENT` becomes optional, with `DEFAULT_USER_AGENT` (repo URL, no contact) as the fallback.

### 3. Step: `step.ts`, `deps.ts`, `receipt.ts`, `link-deps.ts`, `errors.ts`

```ts
export interface StepDeps {
  patternFor(name: PatternName): Pick<Pattern, 'check' | 'fetch'>;
  loadParser(name: string): Promise<ParserModule>;
  link(records: ParsedRecord[], deps: LinkDeps): Promise<LinkResult>;
  writeRows(dbs: DatabaseMap, rows: InboxRow[], opts: { priority: WritePriority; now?: Date }): Promise<WriteResult>;
  startJob(req: JobRequest): Promise<{ jobId?: string }>;
  fetch: typeof fetch; wait(ms: number): Promise<void>; now(): Date; newId(): string;
  log(msg: string, extra?: Record<string, unknown>): void;
}
export function defaultDeps(env: Env): StepDeps; // real modules; wait = scheduler.wait; newId = ulid
export type StepOutcome =
  | { ack: true; status: RunStatus | 'duplicate' | 'stale' | 'invalid' }
  | { ack: false; delaySeconds: number; error: string };
export function runStep(body: unknown, attempts: number, env: Env, deps: StepDeps): Promise<StepOutcome>; // never throws
```

A step, in order:

1. Invalid body → log, ack (`invalid`), no row. Unknown source id → `failed`.
2. Load the cursor and run rows in one D1 batch. A run row not `running` → ack (`duplicate`), change nothing.
3. KV `source:<id>` says ingest off → `skipped`.
4. **Stale.** The stored cursor (kind, value, etag) ≠ `from`: this step already committed (a redelivery) or
   another run moved the cursor. With no run row, insert one as `skipped` (`cursor moved since planning`);
   otherwise change nothing. Ack (`stale`).
5. No run row → insert it as `running`.
6. `PatternContext` gets `userAgent`, `deps.fetch`, `signal: AbortSignal.timeout(300_000)`, `wait`, `log`,
   `now`, `runId`, and `credentials` built only from the optional `GITHUB_TOKEN` (`github`) and `NVD_API_KEY`
   (`nvd`) secrets: nothing else from `env` reaches a pattern. Step 0 only: `check()`; `unchanged` → finish as
   `unchanged`.
7. `fetch()`. Over 40 items (`MAX_ITEMS_PER_STEP`), or `more` with `nextCursor` equal to `from`, is permanent.
   A pattern error with `code: 'not-configured'` (the source has no pull config yet) → finish as `skipped`.
8. **Receipt to R2 before any parsing**, when there is a receipt or an item.
9. `heavy` → `startJob({ ...heavy, requestId: `${runId}-${step}`, cursor: nextCursor })` and finish as `heavy`.
   Don't commit the cursor: ti-api keeps it with the job and commits it only when the job completes, so a
   failed job leaves the source where it was. ti-api uses `requestId` as the job id, so a redelivered step
   finds the same job. The watchdog reports failed jobs.
10. No `source.parser` → finish `ok`, `found` = items, `written` 0. Commit no cursor and ignore `more`.
11. `loadParser` (any failure is permanent), then `parse(item.body)` once per item: each `RawItem.body` is one
    parser input. Accept `ParsedRecord[]` or `ParseResult`. A throwing item is skipped and counted; if all
    throw, fail permanently with the first error, else set `error` to `parse failed for N of M items: …`. A
    source in `link` display mode that has a parser fails permanently: no link-only field filter exists yet.
12. New unknown fields → merge into `unknown-fields:<id>` (≤ 50 names of ≤ 100 characters; `lastSeen` = now).
13. `link(records, linkDeps)`, logging `docs.length` only. Non-empty rows →
    `writeRows(databasesFromEnv(env), rows, { priority: 'steady', now })`; `deferred: true` is retryable.
    **Commit** the cursor as a compare-and-set (`UPDATE cursors … WHERE source_id = ? AND kind = ? AND
    value IS ? AND etag IS ?`, or `INSERT … ON CONFLICT DO NOTHING` when `from` is null). Only if it changed a
    row, add `found`, `written` and `bytes` to the run (on the last step also `ok` and `finished_at`). If it
    changed none, a twin of this step got there first: log, ack, queue nothing.
14. `more` → `JOBS.send({ sourceId, runId, step: step + 1, from: nextCursor })`. If the send fails, finish the
    run as `failed` (`continuation not queued`) and ack; the next scheduled run resumes from the cursor.

`runs` has no step column, so the cursor compare-and-set makes a redelivered `(runId, step)` safe.

- **Errors:** permanent = `PermanentError` (`errors.ts`), `NotImplementedError` (so stubs don't burn retries)
  or `name === 'ZodError'`; the rest are retryable. Permanent → run `failed` with `finished_at` and `error`,
  ack. Retryable → set `error`, keep `running`, `{ ack: false, delaySeconds: retryDelaySeconds(attempts) }`.
  Stored error text is `name: message`, URL query strings removed, ≤ 500 characters. Logs are JSON lines with
  ids, counts and status only: never bodies, secrets or the ops address.
- **Receipt:** key `rawReceiptKey(source.id, runId, step, new Date(decodeTime(runId)))`, so a redelivery
  overwrites the same object and a run's steps share a day folder. Gzipped (`CompressionStream`) NDJSON: a
  `{"type":"receipt",source,runId,step,fetchedAt,contentType,encoding,body}` line (`utf8` or `base64`), then
  `{"type":"item",id,body}` per item; content type `application/gzip`. For a `link` display-mode source the
  lines carry ids and metadata only, no bodies. `bytes` = uncompressed length.
- **Link deps:** `read(table, keys)` routes with `databaseFor` from `@ti/db/tables` (never `ti_users` or
  `ti_control`), allows only `/^[a-z_]+$/` column names, and uses row-value `IN` with ≤ 100 bound parameters
  per statement, in as many statements as the keys need. `lookupCold(key)` reads `lookupVulnKey(key)` from R2
  (a JSON object keyed by vulnerability key) and returns that key's row, or `null` when the file or the key is
  missing. The nightly job that writes these files comes later, so today it always returns `null`.

### 4. Heavy hand-off: `heavy.ts`

`startHeavyJob(env: Pick<Env, 'API' | 'JOB_HMAC_SECRET'>, req: JobRequest, now: Date): Promise<{ jobId?: string }>`

- No `API` binding or no secret → `PermanentError`; never send an unsigned call.
- Serialise the body once; send `content-type: application/json`, `TIMESTAMP_HEADER` (`floor(now / 1000)`) and
  `SIGNATURE_HEADER` = `signRequest(secret, 'POST', '/internal/jobs', timestamp, body)` through
  `env.API.fetch('https://ti-api.internal/internal/jobs', …)`.
- 2xx → `jobId` from the JSON body (`200` with `existing: true` means the job was already started; that is
  success). `429`, `502`, `503` and other `5xx` → retryable `ti-api returned <status>`. `501`
  (`job_kind_not_ready`) and any other `4xx` → `PermanentError` with the status and the error code from the body,
  never the rest of the body.
- Config: `"services": [{ "binding": "API", "service": "ti-api" }]`; `ti-api-staging` in `env.staging`.

### 5. Dead-letter queue: `dlq.ts`

- Consumers for `ti-jobs-dlq` and `ti-jobs-dlq-staging` (batch 10, 3 retries, no DLQ of their own). `index.ts`
  routes batches whose `batch.queue` matches `^ti-jobs-dlq(-staging)?$` to `recordDeadLetters`, others to steps.
- `recordDeadLetters(batch, env, deps)`: a `running` run becomes `failed` with `finished_at` and
  `dead-lettered after <attempts> attempts: <previous error or "none">`; no row → insert a `failed` one;
  finished runs are left alone. Invalid bodies are logged and acked; a D1 error retries.

### 6. Watchdog: `watchdog.ts`, `report.ts`

`runWatchdog(env, deps: { now(): Date; newId(): string; log }): Promise<Finding[]>` runs on `45 14 * * *` after
`plan()`. Each runs even if the other throws; the handler then rethrows the first error. Findings (last 24 h
unless stated):

- **late:** an ingest-on source with no success in 2× its cadence, or none ever and its first run older than
  that; a source with no runs at all is listed as `never run`;
- **drop:** a 3-hourly or daily source whose `found` over 7 days is < 80% of the 7 days before, if that was ≥ 50;
- **unknown fields:** `unknown-fields:` entries with `lastSeen` in the window;
- **budget:** today's or yesterday's `d1_writes` > 80% of `D1_DAILY_WRITE_LIMIT`, `emails_sent` > 80% of
  `EMAIL_DAILY_CAP` (`@ti/core/budget`);
- **failed runs:** `failed` or with an `error`, grouped by source with count and latest error (covers the DLQ);
- **E2B jobs:** `failed` or `timed_out`, or `queued`/`starting`/`running` for over 60 minutes.

`report.ts` is pure: `formatReport(findings, now): { subject, text }` (subject
`Threat Index watchdog <yyyy-mm-dd>: <n> issues` or `: all clear`) and
`buildRawEmail({ from, to, subject, text, date, messageId }): string` with `From`, `To`, `Subject`, `Date`,
`Message-ID` (`<ulid@sender domain>`), `MIME-Version` and `Content-Type: text/plain; charset=utf-8`; CRLF, lines
≤ 998 characters, ≤ 200 findings then `…and N more`; a header value with CR or LF throws. Send one email a day,
also when clear, as a heartbeat: `env.OPS_EMAIL.send(new EmailMessage(from, to, raw))` (`cloudflare:email`)
when `OPS_EMAIL`, `OPS_EMAIL_TO` and `OPS_EMAIL_FROM` are set; otherwise log the counts, `email skipped`.

### 7. Config: `wrangler.jsonc` and `scripts/wrangler-config.mjs`

- Optional placeholders `${NAME?}`: when `NAME` is unset, the array element holding it is dropped (a whole
  binding, never just its address); outside an array, its key is dropped. Each drop logs one line naming the
  variable, never a value. `${NAME}` works as today. `writeTestConfig` gives optional ones no dummy value.
  Export a pure `fillConfig(config, target)`; keep `writeDeployConfig`'s signature.
- Collector config: `send_email` `destination_address: "${TI_OPS_EMAIL?}"`; vars
  `OPS_EMAIL_TO: "${TI_OPS_EMAIL?}"` and `OPS_EMAIL_FROM: "${TI_OPS_EMAIL_FROM?}"` (an address on the Email
  Routing domain); production `USER_AGENT` ends `; ${TI_OPS_EMAIL?})`. Remove `API_BASE` from both sections.
  Add `services` and the DLQ consumers. Staging sends no email. Update the header and secrets comments.
- Node test `test/wrangler-config.test.ts`: an unset required value throws and names it; unset optional values
  drop the `send_email` element and the vars keys; set values fill in; the other section is left alone.

### 8. Wiring and tests

- `index.ts` only wires `scheduled` and `queue`; remove every `TODO` and "unwired stub" comment. In
  `apps/collector/vitest.workers.mts` add a dummy `JOB_HMAC_SECRET`, and stub `API` if the plugin needs it.
- Workers tests call handlers directly (`createMessageBatch`, `createScheduledController`), capture sends
  with fake producers, and clear `runs`, `cursors` and `jobs` first. Patterns, parsers, `link`, `writeRows`,
  `startJob` and `wait` are fakes; the fake `fetch` throws, so no test reaches the internet.
- **planner:** success 1 h ago → not due, 4 h ago → due, never → due, latest `failed` → due, a young
  `running` run → skipped; KV
  `ingest:false` drops an `on` source, `ingest:true` sends a `wait` one, a malformed value keeps `wait` off;
  distinct ULIDs, step 0, `from` = stored cursor; NOTIFY only on the 3-hourly cron. Keep the existing test.
- **step:** `unchanged`; the happy path (receipt in R2 before the fake parser runs, `steady` writes, cursor
  committed, run `ok` with counts); `more` queues step 1 with the next cursor and a `-1` receipt; `writeRows`
  throws → cursor unchanged, retry delay, `error` set; the same message twice → no second continuation, counts
  unchanged; cursor moved → `skipped`; no parser → receipt only; KV ingest off → pattern not called;
  `NotImplementedError`, 41 items, unknown parser → `failed`; a `link` source's receipt has no bodies; unknown
  fields land in KV; `not-configured` → `skipped`; the pattern context carries only the `github` and `nvd`
  credentials; a `heavy` result sends `requestId` and the pending cursor and leaves the stored cursor unchanged.
- **heavy:** the captured request passes `verifyRequest`, fails with a changed body; 500 → retry; no secret →
  `failed`. **dlq:** a `running` run becomes `failed`, a finished one doesn't change. **watchdog:** seeded rows
  give each finding; a fake `OPS_EMAIL` gets one message; no binding → logged, no throw. Node tests cover
  `formatReport` and `buildRawEmail`.

## Not in scope

- Pattern, parser, linker and writer bodies, and ti-api's `/internal/jobs` route: other features build them.
- Rebuilding `docs/` (only the count is logged), `lookup/` reads, nightly and weekly E2B work, `/ops`, the
  immediate DLQ alert and a `ti-jobs` backlog check via `metrics()`.
- Migrations (idempotency uses the cursor, not a new column). Metering the collector's own `runs` and
  `cursors` rows; `writeRows` meters data rows.
- `scripts/deploy.mjs` and `.github/workflows/deploy.yml`. The shared contract already deploys ti-api before
  the collector and passes `TI_OPS_EMAIL` and `TI_OPS_EMAIL_FROM` to the production deploy.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process.
2. `pnpm test:workers` passes with the Workers tests in section 8; `pnpm test` runs the Node tests in 1, 6, 7.
3. `rg -n "TODO|unwired|UNWIRED|<ops-contact>|<domain>|API_BASE" apps/collector` finds nothing.
4. `git diff --name-only main` lists only files under `apps/collector/`, `packages/core/src/settings*.ts`,
   `scripts/wrangler-config.mjs` and `test/wrangler-config.test.ts`.
5. With a dummy `TI_SETTINGS_KV_ID` and the ops variables unset, `node scripts/wrangler-config.mjs production
   collector` succeeds and its output has no `send_email`, `OPS_EMAIL_TO`, `OPS_EMAIL_FROM` or `USER_AGENT`;
   with dummy ops values it has all four. Save both outputs.
6. Proof from the sandbox, with output saved: write `apps/collector/wrangler.test.jsonc` (`writeTestConfig`);
   with `-c` on that file and `--env staging`, apply the `control` migration via `wrangler d1 execute
   ti_control_staging --local --file …`, run `wrangler dev --test-scheduled --port 8700`, then
   `curl "http://localhost:8700/__scheduled?cron=0+*/3+*+*+*"`.
   Show the queued messages (ULID run ids), the step logs and `SELECT status, COUNT(*) FROM runs GROUP BY
   status` (with stub patterns, runs end `failed` with `not implemented`). Trigger `45+14+*+*+*` and show the
   watchdog report logged with the email skipped. Stop the server.
7. The PR lists each Cloudflare fact it relies on, with a docs link and what was checked: the queue limits,
   `scheduler.wait`, the `send_email` binding and raw-message headers, `services` in `env.staging`, KV bulk
   `get` (locally too), D1's bound-parameter limit, and whether `ti-jobs-dlq` must exist before its consumer
   deploys.

## Changes from the first build of this branch

The pull patterns have since merged, and this branch is rebased onto them. One interface changed and two
review nits are left; fix them on top of the existing commits and don't redo work that already matches the spec.

1. **`PatternResult.nextCursor` is now `Cursor | null`.** `null` means there is nothing to commit: a first run
   on a source that found nothing. `tsc` fails today in `step.ts` where the cursor is compared, sent with a
   heavy job and committed. Handle `null` at each point:
   - no cursor commit: the stored cursor stays as it is (absent on a first run), and the run is still recorded
     with its counts;
   - a heavy request sends no `cursor` field;
   - `more: true` with a `null` cursor is a pattern bug: fail the run permanently, don't loop;
   - the stale-step check treats `null` as "no cursor".
   Test each case.
2. **`not-configured` from `check()` is skipped too.** Step 0 calls `check()` outside the `try` that maps a
   pattern error with `code: 'not-configured'` to `skipped`, so today it is retried. Map it the same way for
   both calls. Use the pattern error's `retryable` field for the rest, so the new `cancelled` code is
   retried. Test both.
3. **The watchdog email stays ASCII.** The `…and N more` line is added after `clean()`, so a non-ASCII `…`
   goes into a body sent with no Content-Transfer-Encoding. Use `...and N more`, and count each group's
   findings before cutting the list to 200, so each heading shows the real count. Test it.

`PROOF.md` must describe the whole branch, not only these fixes, because it becomes the PR body. Re-run every
check in the acceptance criteria.

## Changes from the second build of this branch

The round-2 fixes above are committed, and this branch is rebased onto the current `main`. The second build
stopped before review because `pnpm build` failed with `no fixture fixtures/cisa-kev/pattern-catalog-v2.json`
in a checkout that had received new fixture files through git. The code was fine; the cause is Vitest's
persistent module cache (`node_modules/.vitest-cache`). `test/fixtures.ts` expands an eager
`import.meta.glob('../fixtures/*/*')` when it is transformed, and the cache keys that transform on the helper's
own content. A fixture added by a pull or a rebase is therefore invisible until someone deletes the cache. CI
never sees this because it starts with no cache.

1. Make new and changed fixture files always visible to `fixture()`, in `pnpm test` and `pnpm test:workers`,
   without deleting any cache by hand. Prefer the smallest fix: turn the persistent module cache off for the
   test runs, or make its key cover the fixture files. Find the exact option in the installed Vitest (its
   types or docs in `node_modules`), name it in the PR, and explain in a comment where you set it.
2. Prove it: with the cache populated by a first run, add a new file under `fixtures/`, run the fixtures test
   again without clearing anything, and show it is found. Save that output as proof, then remove the file.
3. Note in the `PROOF.md` Risk section that the previous loop run never reviewed the round-2 commit, so this
   review covers it.

`PROOF.md` must describe the whole branch. Re-run every check in the acceptance criteria.
