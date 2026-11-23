# loader-budget: load inbox chunks into D1 inside the daily write budget

## Why

E2B jobs leave hot rows in R2 as gzipped NDJSON chunks (`inbox/<jobId>/<n>.ndjson.gz`), and the API queues one
`ti-load` message per chunk. Today the loader reserves budget for a chunk and acks it without writing anything,
and `writeRows()` in `packages/db/src/write.ts`, shared by the loader and the collector, is a stub.

This change makes both real. `writeRows()` routes rows to their databases, rejects bad rows, writes them in a
few batched statements and counts every row in the daily budget: steady writes always go through, first-load
writes stop at the cap. The loader reads one chunk per message, writes it, deletes it, and moves a first-load
chunk to the next UTC day when the cap is used up.

Other features are built at the same time on their own branches; the collector calls `writeRows()` with
`priority: 'steady'`, so its signature must not change. This branch edits only `apps/loader/**`,
`packages/db/src/**`, new files in `packages/db/test/`, `packages/db/vitest.workers.mts`,
`packages/core/src/budget.ts` and a new `packages/core/src/budget.test.ts`.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/loader/src/consume.ts` | Reserves `msg.body.rows` writes before reading anything, then acks without writing (a TODO). On a full budget it calls `msg.retry({ delaySeconds })`, capped at 12 h. `Env` has only `DB_CONTROL` and `BUCKET` |
| `apps/loader/wrangler.jsonc` | Five D1 bindings (no `ti_users`), `BUCKET`, consumer of `ti-load` / `ti-load-staging` with `max_batch_size: 1`, `max_retries: 10`. No producer binding, no dead-letter queue, no `migrations_dir`. `workers_dev` and `preview_urls` are off |
| From seams | `LoadMessage`, `InboxRow`, `MAX_ROWS_PER_CHUNK = 500` and `inboxChunkKey()` in `@ti/core/inbox`; `databasesFromEnv()` (real) and `writeRows()` (throws `NotImplementedError`) in `@ti/db/write`; `apps/loader/vitest.workers.mts` with an empty-batch smoke test |
| `packages/db/src/sql.ts` | `upsertNewerSql()` builds a `VALUES` upsert, one bound parameter per cell, `modified` hard-coded. Nothing calls it. `MAX_STATEMENTS_PER_INVOCATION = 40` |
| Schema | Drizzle tables in `packages/db/src/schema/*.ts` (22 tables, checked against `PRAGMA table_info`). `modified`: `vulns`, `advisories`, `breach_notices`, `breach_events`, `incidents`. `updated_at`: `sources`, `cursors`. Secondary indexes on `runs`, `advisories`, `changes`, `breach_notices`, `watch`. No foreign keys |
| `packages/core/src/budget.ts` | `reserveWrites(db, n, priority, now?)`. Steady: insert-if-missing plus an unchecked `UPDATE` (a negative `n` lowers the meter). First load: `UPDATE … WHERE d1_writes + n <= 90000`. Nothing reads today's usage or gives a reservation back |

Cloudflare limits this relies on, checked against the docs on 23 November 2026. Plan §18 lists the D1 and delay
limits as unverified. If the sandbox can reach `developers.cloudflare.com`, check again and note any change.

| Limit | Value (docs page) |
| ----- | ----------------- |
| D1 per statement | 100 bound parameters; 100,000-byte SQL text; 2,000,000-byte string or row (`d1/platform/limits`) |
| D1 per invocation | 1,000 queries (Paid), 50 (Free); a `batch()` counts as one query and has 30 s (same page) |
| D1 JSON | `json_each` and `json_extract` are supported; the docs bind an array as one parameter (`d1/sql-api/query-json`) |
| Queues | `delaySeconds` up to 24 h (the code assumes 12 h); at most 100 retries; retention 24 h on Free, up to 14 days on Paid (`queues/platform/limits`). After `max_retries` a message is deleted, or sent to a dead-letter queue if set; the docs don't say whether `msg.retry()` counts, so nothing below depends on it (`queues/configuration/batching-retries`) |

With 100 parameters, a `VALUES` upsert fits 4 `vulns` rows (22 columns): a 500-row chunk needs 125 statements,
over our own cap of 40. So the writer binds a group of rows as one JSON parameter.

## What to build

### 1. Table details: `packages/db/src/table-info.ts`

`packages/db/src/tables.ts` (`TABLE_DATABASE`, `databaseFor`) already exists on main as part of the shared
contract; don't edit it. This new file adds what the writer needs on top, and a test checks that every
table's `db` here equals `databaseFor(name)`.

```ts
export type WriteRule = 'newer' | 'upsert' | 'keep-first-seen' | 'insert-ignore' | 'none';
export interface ColumnInfo { type: 'text' | 'integer' | 'real'; notNull: boolean; hasDefault: boolean }
export interface TableInfo {
  name: string; db: DatabaseName; columns: ReadonlyMap<string, ColumnInfo>; primaryKey: readonly string[];
  secondaryIndexes: number; rule: WriteRule; versionColumn?: 'modified' | 'updated_at';
}
export const TABLES: ReadonlyMap<string, TableInfo>;
export const WRITE_ORDER: readonly string[];          // every writable table
export const DB_WRITE_ORDER: readonly DatabaseName[]; // ti_control, ti_world, ti_signals, ti_vulns, ti_advisories
```

Build `TABLES` at load from the six schema modules with Drizzle's `getTableConfig()`; a table's database is its
module. Column keys are SQL names (`source_id`, not `sourceId`), as are `InboxRow.row` keys. A table with
`modified` or `updated_at` is `newer` on that column; name the others' rules in one object:

| Rule | Tables | On conflict |
| ---- | ------ | ----------- |
| `newer` | `vulns`, `advisories`, `breach_notices`, `breach_events`, `incidents` (`modified`); `sources`, `cursors` (`updated_at`) | Update the supplied non-key columns only `WHERE excluded.<v> > <table>.<v>`. An older copy, or an older job's cursor, never wins |
| `upsert` | `runs`, `jobs`, `techniques`, `vuln_techniques`, `companies` | Update the supplied non-key columns (`DO NOTHING` if none) |
| `keep-first-seen` | `signals` | As `upsert`, but `first_seen` is never updated |
| `insert-ignore` | `changes` | `DO NOTHING`: append-only, keyed by ULID, so a redelivered row is a no-op |
| `none` | `budget`, the seven `ti_users` tables | Refused: only `budget.ts` writes the meter, only the API writes accounts |

`WRITE_ORDER`: `sources`, `cursors`, `runs`, `jobs`, `techniques`, `companies`, `vuln_techniques`, `breach_events`,
`breach_notices`, `incidents`, `signals`, `changes`, `vulns`, `advisories`. With no foreign keys this only makes
results deterministic; load order across chunks is the producer's job.

### 2. Statement planner: `packages/db/src/plan.ts` and `sql.ts`

```ts
export const MAX_PARAM_BYTES = 1_000_000; // half of D1's 2,000,000-byte string limit
export class RowValidationError extends Error { readonly index: number; readonly table: string | undefined }
export class WriteLimitError extends Error {}
export interface PlannedStatement { db: DatabaseName; table: string; op: 'upsert' | 'delete'; sql: string; params: [string]; rows: number }
export interface WritePlan { statements: PlannedStatement[]; rows: number; cost: number }
export function planWrites(rows: readonly InboxRow[]): WritePlan; // pure, no I/O
```

In this order; any failure throws before anything is written:

1. More than `MAX_ROWS_PER_CHUNK` rows: `WriteLimitError`.
2. Each row: `table` is in `TABLES` and not `none`; `op` is `upsert` or `delete`; `row` is a plain object whose
   keys are all columns of the table; every primary-key column is present and not null. An upsert carries every
   `NOT NULL` column without a default (SQLite checks `NOT NULL` before the conflict). A delete carries only
   key columns. Else `RowValidationError`, naming the row index, table and column, never a value.
3. Values: a string; a finite number (an integer in `integer` columns); a boolean (stored 1/0, `integer` only);
   `null`; or, in `text` columns only, an array or plain object (stored as `JSON.stringify` text). Anything else
   (`undefined`, `NaN`, a bigint, a number in a `text` column, a string in a number column) is rejected.
4. A primary key repeated in one call: the last row wins, so results don't depend on grouping.
5. Group by table (`WRITE_ORDER`), op (upserts first), then exact column set. A row updates only its columns.
6. One statement per group, binding exactly one parameter: a JSON array of its rows. Split a group before the
   JSON passes `MAX_PARAM_BYTES`; one row over the limit is a `RowValidationError`.
7. More than `MAX_STATEMENTS_PER_INVOCATION` (40) statements: `WriteLimitError`.
8. `cost` sums (1 + the table's secondary indexes) per row: D1 counts index writes as rows written.

Add `jsonUpsertSql(t: TableInfo, cols: readonly string[])` and `jsonDeleteSql(t: TableInfo)` to `sql.ts`. Names
in SQL come only from `TableInfo`, never from row data. Shapes:

```sql
INSERT INTO vulns (key, …, modified) SELECT json_extract(value, '$.key'), …, json_extract(value, '$.modified')
  FROM json_each(?1) WHERE true
  ON CONFLICT (key) DO UPDATE SET kind = excluded.kind, … WHERE excluded.modified > vulns.modified
DELETE FROM advisories WHERE (source, source_id) IN
  (SELECT json_extract(value, '$.source'), json_extract(value, '$.source_id') FROM json_each(?1))
```

`WHERE true` is required when an upsert takes its rows from a `SELECT`. Keep `upsertNewerSql` and
`MAX_STATEMENTS_PER_INVOCATION`; replace the "verify" note with the checked limit (100).

### 3. `writeRows()`: `packages/db/src/write.ts`

Keep the seams signature exactly:
`writeRows(dbs: DatabaseMap, rows: InboxRow[], opts: { priority: WritePriority; now?: Date }): Promise<WriteResult>`.

1. No rows: return `{ written: 0, statements: 0, deferred: false }` with no queries.
2. `planWrites(rows)`; then `dbs` must hold `ti_control` and every database the plan uses, else throw naming
   the missing one. Both happen before any I/O.
3. `first-load`: `reserveWrites(ti_control, plan.cost, 'first-load', now)`. If false, return
   `{ written: 0, statements: 0, deferred: true }` without writing.
4. One `batch()` per database, in `DB_WRITE_ORDER`, one after another. `written` sums `meta.changes`;
   `statements` is `plan.statements.length`.
5. If a batch throws: for `first-load`, `releaseWrites(ti_control, plan.cost, now)` (log a failed release, don't
   throw it over the original), then rethrow. Committed batches stay; a retry is safe as every rule is idempotent.
6. `steady`: after every batch succeeds, `reserveWrites(ti_control, plan.cost, 'steady', now)`.

Rows that "newer wins" skips still count, so the meter errs high. `@ti/db` must list `@ti/core` as a dependency
(seams adds it for `write.ts`); if not, stop and say so in the PR, as this branch may not change `pnpm-lock.yaml`.

### 4. Budget: `packages/core/src/budget.ts`

Keep `reserveWrites(db, n, priority, now?)`, its return value, `utcDay`, `secondsUntilUtcMidnight` and the constants.

- `n` must be a non-negative safe integer, else `RangeError`; `n = 0` returns true with no query. A first-load
  `n` above `FIRST_LOAD_DAILY_CAP` is a `RangeError`: it could never fit and would defer forever.
- Steady is one statement: `INSERT INTO budget (day, d1_writes) VALUES (?1, ?2) ON CONFLICT (day) DO UPDATE SET
  d1_writes = d1_writes + excluded.d1_writes`. The first-load cap check stays one atomic statement.
- New `releaseWrites(db, n, now?)`: subtracts `n` from that day, never below 0.
- New `budgetUsage(db, now?)` for the watchdog and `/ops`: `{ day, d1Writes, firstLoadCap, dailyLimit,
  firstLoadRemaining }`, zeros when today has no row. Read only.
- The header calls these free-plan limits; say they are caps the project keeps for itself.

### 5. Loader: `apps/loader/src/`

`index.ts` still only wires `queue()` to `consume()`. Add `chunk.ts`, `delays.ts`, `failure.ts` and `inbox-tables.ts`.
`Env` gains `DB_VULNS`, `DB_ADVISORIES`, `DB_SIGNALS`, `DB_WORLD` and `LOAD: Queue<LoadMessage>`. Per message:

1. Check the body: `jobId` matches `^[A-Za-z0-9_-]{1,64}$`; `chunkKey` equals `inboxChunkKey(jobId, n)` for an
   integer `n ≥ 0`; `rows` is 1–500; `priority` is `steady` or `first-load`. A bad body is logged and acked with
   no R2 access: the loader deletes what it loads, so it must never touch a key outside `inbox/<jobId>/`.
2. `BUCKET.get(chunkKey)` returns nothing: the chunk was already loaded and deleted. Log and ack.
3. `readChunk()` throws `CorruptChunkError`, with a reason naming the line, for: over 4 MiB stored; a gunzip error
   (`DecompressionStream('gzip')`); over 16 MiB unzipped (stop reading there); bad UTF-8; a line that isn't JSON
   `{ table, op, row }`; a line count other than `rows`; a table not in `INBOX_TABLES`.
4. `writeRows(databasesFromEnv(env), rows, { priority, now })`.
5. `deferred`: `LOAD.send(body, { delaySeconds: deferDelaySeconds(now) })`, log, ack; the chunk stays.
   `deferDelaySeconds` is `min(86_400, secondsUntilUtcMidnight(now) + 60)`, so one hop reaches the next day.
   Send a fresh message rather than `msg.retry()`: a first load lasts about two weeks, and retries would use up
   `max_retries` and could outlive message retention.
6. Written: delete the chunk, log, ack. If the delete fails, the retry rewrites the same rows and deletes again.
7. Corrupt (`CorruptChunkError`, `RowValidationError`, `WriteLimitError`, or a D1 error containing
   `constraint failed`, such as the `CHECK` on `signals.kind`): `recordLoadFailure()`, log, ack, keep the chunk
   for inspection. No retry.
8. Anything else: `msg.retry({ delaySeconds: min(3600, 30 × 2^(attempts − 1)) })`. On the last delivery
   (`msg.attempts > LOADER_MAX_RETRIES`, 10, matching `wrangler.jsonc`; confirm against the docs and say so in
   the PR), call `recordLoadFailure()` first: with no dead-letter queue, the message is then gone.

- `INBOX_TABLES`: `vulns`, `advisories`, `signals`, `changes`, `techniques`, `vuln_techniques`, `companies`,
  `breach_notices`, `breach_events`, `incidents`. Inbox data comes from a sandbox, so no `ti_control` table can
  be written from it: not licence switches (`sources`), cursors, run and job bookkeeping, or the budget meter.
  How a first-load job hands its final cursor to the collector is decided by the heavy-jobs work, not here.
- `recordLoadFailure(db, jobId, reason, now)`: `UPDATE jobs SET status = 'failed', error = COALESCE(error, ?),
  finished_at = COALESCE(finished_at, ?) WHERE id = ?` with `"<chunkKey>: <reason>"` (≤ 500 characters), counted
  as one steady write; with no job row, the log is the record. No migration: `jobs.error` and `failed` exist.
- Logs: one JSON object per line: `event` (`load_ok`, `load_missing`, `load_deferred`, `load_failed`,
  `load_retry`, `load_bad_message`), `jobId`, `chunkKey`, counts or a reason. Never row contents.

### 6. Loader config: `apps/loader/wrangler.jsonc`

- Add a producer binding `LOAD` for the queue it already consumes (`ti-load`, staging `ti-load-staging`).
- Keep `max_batch_size: 1` (one chunk per invocation bounds the work) and `max_retries: 10`. Add
  `max_concurrency: 5`: deferred chunks all wake just after midnight UTC, and this caps parallel D1 writers.
- Add `migrations_dir` to each D1 binding, as `apps/api/wrangler.jsonc` does, for `wrangler d1 migrations apply`.
- No dead-letter queue, fetch handler or route; `workers_dev` and `preview_urls` stay off.

### 7. Tests

None touches the internet. Local D1 may not enforce production limits, so the planner tests prove them.

- `packages/db/src/tables.test.ts` (Node): read the migrations with `import.meta.glob('../migrations/*/*.sql',
  { query: '?raw', import: 'default', eager: true })`, as `test/fixtures.ts` does. Each `CREATE TABLE` is in
  `TABLES` exactly once, in its folder's database, and nothing else is; every table has a rule.
- `packages/db/src/plan.test.ts` (Node): every rejection in section 2; a 500-row `vulns` group with 300-character
  summaries plans to ≤ 40 one-parameter statements; splitting at `MAX_PARAM_BYTES`; 501 rows; 41 groups;
  duplicates; `cost` (an `advisories` row costs 2); the SQL for each rule.
- `packages/core/src/budget.test.ts` and `apps/loader/src/delays.test.ts` (Node): `deferDelaySeconds` is 90 at
  23:59:30Z, 43,260 at 12:00Z and 86,400 at 00:00:00Z; the retry backoff.
- `packages/db/test/write.workers.test.ts`: every rule in sections 1–3 against local D1, including one `batch()`
  per database (wrap each `D1Database` to count), equal or older versions changing nothing, partial rows, stored
  types (`typeof()`), the same call twice, a validation error writing and counting nothing, steady at 150,000,
  first-load deferred at 89,990 with cost 20, and a failed first-load batch (a `CHECK`) releasing its reservation.
- `packages/db/test/budget.workers.test.ts`: 90,000 exactly passes and one more doesn't; 20 parallel first-load
  reservations never pass the cap; bad `n`; `releaseWrites` stops at 0; `budgetUsage`.
- `apps/loader/test/consume.workers.test.ts`: every path in section 5, using
  `apps/loader/test/fixtures/sample-chunk.ndjson` (a row for each `INBOX_TABLES` table, plus one delete) gzipped
  with `CompressionStream` into local R2, and a stub `LOAD`. Include a failed chunk delete followed by redelivery
  (identical rows), and a bad body next to another object under the prefix (it survives).

### 8. Proof in the sandbox

Add `apps/loader/dev/producer.ts` and `apps/loader/dev/wrangler.jsonc`: a local-only Worker whose one route,
`POST /send`, puts its JSON body on `ti-load` (binding `LOAD`), with a header saying it is never deployed (`scripts/deploy.mjs`
deploys only `apps/<app>/wrangler.jsonc`). Include `dev` and `test` in `apps/loader/tsconfig.json`.

With `TI_LOOP_SANDBOX=1`, give every `wrangler d1` and `wrangler r2` command `-c apps/loader/wrangler.jsonc
--local --persist-to .wrangler/loader-proof`. Set up before starting the server; query after stopping it.

1. Apply the five databases' migrations; insert a `jobs` row `dev-job`; set today's `d1_writes` to 90,000. With
   `wrangler r2 object put threat-index/<key> --file …`, put the gzipped fixture at `inbox/dev-job/0.ndjson.gz`
   and `1.ndjson.gz`, and plain text at `2.ndjson.gz`.
2. `wrangler dev -c apps/loader/dev/wrangler.jsonc -c apps/loader/wrangler.jsonc --persist-to
   .wrangler/loader-proof --port 8700`. `curl -X POST localhost:8700/send` chunk 0 `steady`, chunk 0 again,
   chunk 1 `first-load`, chunk 2 `steady`, waiting for each log line.
3. Stop the server. Query row counts, today's `budget` row and the `jobs` row; `wrangler r2 object get` chunks 0–2.

Expected: `load_ok` (rows in every inbox table; steady goes through above the cap), `load_missing`,
`load_deferred` (chunk 1 kept, no new rows), `load_failed` (job `failed`, chunk 2 kept); chunk 0 gone. Save the
commands and output, and stop every server you started.

## Not in scope

- Writing inbox chunks or manifests (E2B jobs) and queueing `ti-load` messages (`internal-jobs.ts`). The loader
  doesn't read `manifest.json`. How the collector calls `writeRows()`; linker rules; `docs/vuln/<key>.json`.
- Marking a job loaded after its last chunk, deleting manifests, cleaning up failed chunks; new cap values.
- A `ti-load` dead-letter queue, retention settings or any other new Cloudflare resource.
- Migrations (none is needed), other apps, seams files other than `write.ts`, `vitest.workers.config.mts`,
  `pnpm-lock.yaml`, dependency lists, and `docs/IMPLEMENTATION_PLAN.md` (other branches edit §18 at the same
  time; put the checked limits in the PR body and in code comments).

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process.
2. `pnpm test:workers` passes in the sandbox: every test in section 7, plus the existing api, collector, db and
   loader tests.
3. `writeRows` and `databasesFromEnv` keep their seams signatures. Every migration table maps to exactly one
   database; `budget`, `ti_users`, and (from the inbox) `sources`, `runs` and `jobs` can't be written.
4. Every planned statement binds one parameter of at most `MAX_PARAM_BYTES`; no call plans more than 40 data
   statements; a 500-row `vulns` chunk loads in one call.
5. First-load over the cap writes nothing and returns `deferred: true`; steady always writes and is counted; a
   failed first-load write gives its reservation back.
6. A chunk is deleted only after a successful write; a missing chunk acks; a deferred chunk is re-sent with a
   delay of at most 86,400 s; no key outside `inbox/<jobId>/` is read or deleted; a corrupt chunk is not retried,
   stays in R2 and leaves its reason on the `jobs` row.
7. `git diff --name-only main` lists only `apps/loader/**`, `packages/db/src/**`, `packages/db/test/**`,
   `packages/db/vitest.workers.mts`, `packages/core/src/budget.ts` and `packages/core/src/budget.test.ts`.
   `apps/loader/wrangler.jsonc` adds only `LOAD`, `max_concurrency` and `migrations_dir`; no fetch handler.
8. The PR body lists the Cloudflare limits above, says whether they were re-checked, and explains the JSON
   statement form and why deferral re-sends instead of retrying.
9. Proof saved: `pnpm build` and `pnpm test:workers` output, and the section 8 run with its commands, log lines
   and query results.

## Changes from the first build of this branch

This branch already implements the spec above, and its code review converged. Three things are left; fix them
on top of the existing commits and don't redo work that already matches the spec.

1. **A failed R2 read is retryable, not corrupt.** Today any error while reading the gzip stream becomes
   `CorruptChunkError('not valid gzip')`, so a transient R2 body failure partway through marks the job
   `failed` and the chunk is never retried. Only a real format problem (bad gzip header or data, bad JSON, a
   row that fails validation) is corrupt. An error from the underlying R2 body stream is retryable, with the
   normal backoff. Test a stream that errors partway through.
2. **The last delivery always leaves a record.** When `recordLoadFailure` throws on a delivery where
   `msg.attempts > LOADER_MAX_RETRIES`, log `load_failed` with the chunk key and reason before the message is
   dropped, so the failure is never silent. Test it.
3. **Constraint errors are classified by where they happen.** A `constraint failed` error counts as a bad
   chunk only when it comes from a data-row statement. One from the budget or control statements in
   `writeRows` is retryable. Test both.

`PROOF.md` must describe the whole branch, not only these fixes, because it becomes the PR body. Re-run every
check in the acceptance criteria.
