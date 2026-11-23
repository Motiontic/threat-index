# seams: shared contracts for the plumbing features

## Why

Six plumbing features are built next, on separate branches at the same time: the pull patterns, the
collector runtime, the loader and its budget, the E2B bridge, the linker and the web shell. Each owns its
own files, but they meet at a few points:

- the collector's step calls a pattern, a parser, the linker and a database writer;
- E2B jobs write inbox chunks that the loader reads, and the API's job callback queues load messages;
- the collector asks the API to start an E2B job, and the sandbox calls the API back;
- two of them need new dependencies, but only one branch at a time may change `pnpm-lock.yaml`.

Today some of these meeting points don't exist on `main`. The load message type lives inside the loader,
the linker has no entry point, there is no shared database writer, and the job callback signature covers
only the job id. This change puts each meeting point on `main` as a type, a pure helper or a stub, so every
feature fills in a stub it owns and none needs another feature's branch.

It adds no product behaviour.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/patterns/src/types.ts` | `PatternContext` has `source`, `cursor`, `userAgent`, `fetch`, `signal`. No way to wait without CPU, log, or read the time |
| `packages/patterns/src/<name>.ts` | Seven stubs exporting `check()` and `fetch()`. Nothing maps a `PatternName` to its module |
| `apps/loader/src/consume.ts` | Declares `LoadMessage` itself. Nothing else can import it |
| `packages/linker/src` | `detect.ts` (hot-set rule, EPSS bands). No function that turns parsed records into rows |
| `packages/db/src` | `databases.ts` (`DATABASES`, `DatabaseName`), `sql.ts` (`upsertNewerSql`). No writer that routes rows to databases |
| `apps/api/src/lib/auth.ts` | `hmacHex`, `verifyHmac`. `/internal/jobs/:id/*` accepts `HMAC(JOB_HMAC_SECRET, jobId)`: no expiry, not bound to method, path or body |
| `ti_control.runs.status`, `ti_control.jobs.status` | Free text. No agreed values |
| `apps/api/package.json` | No E2B SDK, no R2 request signer |

## What to build

### 1. Inbox and load messages: `packages/core/src/inbox.ts`

```ts
import type { WritePriority } from './budget';

export const MAX_ROWS_PER_CHUNK = 500;

/**
 * One D1 row on its way in. `table` is a table name from packages/db/migrations, and the keys of `row`
 * are that table's SQL column names (`source_id`, not `sourceId`).
 */
export interface InboxRow {
  table: string;
  op: 'upsert' | 'delete';
  row: Record<string, unknown>;
}

/** Written by a sandbox. Carries no priority: ti-api sets that from the job kind. */
export interface InboxChunkRef {
  key: string; // inbox/<jobId>/<n>.ndjson.gz
  rows: number;
}

export interface InboxManifest {
  jobId: string;
  createdAt: string; // ISO
  chunks: InboxChunkRef[];
}

/**
 * One ti-load message: one inbox chunk. ti-api sets `priority` from the job's kind (`first-load` jobs →
 * 'first-load', every other kind → 'steady'), never from anything the sandbox wrote, so a sandbox can't
 * skip the first-load cap.
 */
export interface LoadMessage {
  jobId: string;
  chunkKey: string;
  rows: number;
  priority: WritePriority;
}

export function inboxChunkKey(jobId: string, n: number): string;    // inbox/<jobId>/<n>.ndjson.gz
export function inboxManifestKey(jobId: string): string;            // inbox/<jobId>/manifest.json
```

`apps/loader/src/consume.ts` imports `LoadMessage` from `@ti/core/inbox` and no longer declares it. No other
change to the loader.

### 2. R2 keys: `packages/core/src/r2-keys.ts`

Pure functions, each with a test:

- `rawReceiptKey(sourceId, runId, step, at: Date)` → `raw/<source>/<yyyy>/<mm>/<dd>/<runId>-<step>.ndjson.gz`
  (UTC date);
- `jobPrefix(jobId)` → `jobs/<jobId>/`;
- `vulnDocKey(vulnKey)` → `docs/vuln/<key>.json`;
- `vulnShard(vulnKey)` → three lowercase hex digits (`000`–`fff`, 4,096 shards): FNV-1a 32-bit of the
  normalised key, modulo 4,096. Synchronous, so Workers and the nightly E2B job compute the same shard.
  Test it against fixed known values;
- `lookupVulnKey(vulnKey)` → `lookup/vuln/<shard>.json`. The file is a JSON object keyed by normalised
  vulnerability key; each value is a row shaped like a `vulns` row. The nightly job that writes these files
  comes later.

### 3. Run and job vocabulary: `packages/core/src/control.ts`

```ts
export const RUN_STATUSES = ['running', 'unchanged', 'ok', 'heavy', 'skipped', 'failed'] as const;
export type RunStatus = (typeof RUN_STATUSES)[number];

export const JOB_STATUSES = ['queued', 'starting', 'running', 'complete', 'failed', 'timed_out'] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

/** What the collector sends to ti-api to start an E2B job. */
export interface JobRequest {
  /**
   * Deterministic for the step that asked (`<runId>-<step>`). ti-api uses it as the job id, so a
   * redelivered request finds the existing job instead of starting a second sandbox.
   */
  requestId: string;
  kind: 'first-load' | 'epss-diff' | 'big-file';
  sourceId: string;
  reason: string;
  url?: string;
  /**
   * The cursor the source moves to once this job has done its work. ti-api keeps it with the job
   * (under jobs/<id>/) and writes it to ti_control.cursors only when the job completes successfully.
   */
  cursor?: Cursor;
}
```

`Cursor` comes from `./types`. A pattern can't know the run's request id or decide the cursor commit, so in
`packages/patterns/src/types.ts` make `HeavyJobRequest` exactly `Omit<JobRequest, 'requestId' | 'cursor'>`. The
collector adds `requestId` and the pattern's `nextCursor` when it sends the request, so there is one shape.

### 4. Request signing: `packages/core/src/sign.ts`

One scheme for every internal call: the collector asking ti-api to start a job, and a sandbox calling
`upload-urls` and `complete`. Implement it fully, with tests. It uses only Web Crypto, so it runs in Workers,
Node 22 and E2B.

```ts
export const SIGNATURE_HEADER = 'x-ti-signature';
export const TIMESTAMP_HEADER = 'x-ti-timestamp';
export const MAX_SKEW_SECONDS = 300;

/** hex(HMAC-SHA256(key, `${METHOD}\n${path}\n${timestamp}\n${hex(SHA-256(body))}`)). */
export function signRequest(key: string, method: string, path: string, timestamp: number, body: string): Promise<string>;

/** Constant-time check, rejects a timestamp more than MAX_SKEW_SECONDS from `now`. Fails closed on a missing key. */
export function verifyRequest(
  key: string | undefined,
  req: { method: string; path: string; timestamp: string | null; signature: string | null; body: string },
  now?: Date,
): Promise<boolean>;

/**
 * The per-job key a sandbox gets: hex(HMAC-SHA256(secret, `job:${jobId}`)). The sandbox never sees `secret`.
 * Throws on an empty secret.
 */
export function deriveJobKey(secret: string, jobId: string): Promise<string>;
```

- `path` is the URL path without the query string.
- Tests cover a good signature, a changed method, path, body or timestamp, a stale timestamp, a missing key
  and a missing header.
- Keep `hmacHex` and `verifyHmac` in `apps/api/src/lib/auth.ts`; unsubscribe tokens still use them. Don't
  switch `internal-jobs.ts` to the new scheme here: the E2B bridge does that.

The start route's answers, recorded here in a doc comment on `JobRequest` so both sides build to them:
`POST /internal/jobs` answers `201 { jobId, status }` for a new job and `200 { jobId, status, existing: true }`
when the request's job, or an active job of the same kind and source, already exists. Callers treat `429`,
`502` and `503` as retryable, and every other `4xx` and `501` as permanent.

### 5. Pattern context and lookup

- Add to `PatternContext` in `packages/patterns/src/types.ts`:
  - `wait(ms: number): Promise<void>`: in Workers this is `scheduler.wait`, which uses no CPU;
  - `log(msg: string, extra?: Record<string, unknown>): void`;
  - `now(): Date`;
  - `runId?: string`, copied into the receipt;
  - `credentials?: Readonly<Partial<Record<CredentialName, string>>>`, with
    `export type CredentialName = 'github' | 'nvd'` added to `packages/core/src/types.ts` (core, so source
    config can name a credential without depending on `@ti/patterns`). The collector fills it from its
    optional `GITHUB_TOKEN` and `NVD_API_KEY` secrets and passes nothing else from its environment. A pattern
    sends a credential only to the origin it belongs to.
- A parser's input is one `RawItem.body`. A pattern that fetches a whole document returns, per item, that
  document with its records array cut to the one entry, so a whole-document parser such as `kev` works
  unchanged.
- New `packages/patterns/src/by-name.ts`: `patternFor(name: PatternName)` returns that pattern's module
  (`{ check, fetch }`), using static imports of the seven files. Test that every `PatternName` resolves.
- After this change, `types.ts` only gains optional fields. Changing an existing field breaks the collector,
  which is built against this interface at the same time.

### 6. Linker entry point: `packages/linker/src/link.ts` (stub)

```ts
import type { InboxRow } from '@ti/core/inbox';
import type { ParsedRecord } from '@ti/core/types';

export interface LinkDeps {
  /**
   * Current rows for these keys, for alias lookups and change detection. Each key is an object of the
   * table's primary-key columns, using the real column names. The linker calls this at most once per
   * table per link(); the implementation splits the keys into as many queries as D1's bound-parameter
   * limit needs.
   */
  read(table: string, keys: Record<string, unknown>[]): Promise<Record<string, unknown>[]>;
  /**
   * Cold-vulnerability summary from lookup/vuln/<shard>.json, used to promote a cold flaw: a row shaped
   * like a `vulns` row (same column names). Null if none.
   */
  lookupCold(vulnKey: string): Promise<Record<string, unknown> | null>;
  now(): Date;
  newId(): string;
}

export interface LinkResult {
  /** Every D1 write, including `changes` rows. Only hot-set entities. */
  rows: InboxRow[];
  /** Vulnerability keys whose docs/vuln/<key>.json must be rebuilt. */
  docs: string[];
  /** Cold records left out of D1 (they reach lake/ through the nightly fold). */
  skipped: number;
}

export async function link(records: ParsedRecord[], deps: LinkDeps): Promise<LinkResult>;
```

The body throws `NotImplementedError` from `@ti/core/errors`. The linker feature fills it in.

### 7. Database writer: `packages/db/src/write.ts` (stub plus one real helper)

```ts
import type { WritePriority } from '@ti/core/budget';
import type { InboxRow } from '@ti/core/inbox';
import type { DatabaseName } from './databases';

export type DatabaseMap = Partial<Record<DatabaseName, D1Database>>;

/** Real: maps DB_CONTROL → ti_control, DB_VULNS → ti_vulns, and so on, from a Worker's env. */
export function databasesFromEnv(env: Record<string, unknown>): DatabaseMap;

export interface WriteResult {
  written: number;
  statements: number;
  /** True when a first-load write was not made because today's budget is used up. */
  deferred: boolean;
}

/**
 * Routes each row to its database, writes newer-wins upserts and deletes within the statement and
 * bound-parameter limits, and counts every row in the ti_control budget. Steady writes always proceed.
 */
export async function writeRows(dbs: DatabaseMap, rows: InboxRow[], opts: { priority: WritePriority; now?: Date }): Promise<WriteResult>;
```

`databasesFromEnv` is implemented and tested. `writeRows` throws `NotImplementedError`; the loader feature
fills it in.

Also implement `packages/db/src/tables.ts`:

```ts
/** Which database each table lives in, derived from the Drizzle schemas in ./schema. */
export const TABLE_DATABASE: Readonly<Record<string, DatabaseName>>;
export function databaseFor(table: string): DatabaseName; // throws on an unknown table
```

Test that every table in every `0001_init.sql` is mapped exactly once. The writer, the collector and the
linker all use this one map.

### 7a. Sensitive paths

Add to `review.sensitivePaths` in `loops.json`, so a human reviews them: `apps/api/src/lib/e2b*`,
`apps/api/src/lib/presign*`, `packages/core/src/sign*`. Keep `REVIEW.md` in step if it lists the paths.

### 7b. Deploy order

The collector will call ti-api through a service binding, so ti-api must deploy first. In
`scripts/deploy.mjs`, change `DEPLOY_ORDER` to `['loader', 'notify', 'api', 'collector']`. Nothing else
in the deploy scripts or workflows changes.

### 7c. Deploy workflow variables

Two features need new deploy-time values, and both would otherwise edit `.github/workflows/deploy.yml`. Add
them here, to the production job's `env` only (staging sends no email and already has its app URL):
`TI_OPS_EMAIL: ${{ vars.TI_OPS_EMAIL }}`, `TI_OPS_EMAIL_FROM: ${{ vars.TI_OPS_EMAIL_FROM }}` and
`TI_APP_URL: ${{ vars.TI_APP_URL }}`. Nothing reads them yet, and an unset variable is an empty string.

### 8. One Workers test project file per app

`vitest.workers.config.mts` defines every app's test project, with each app's dummy secrets inline. Three
features need to change their own app's project, so this shared file would conflict.

- Move the `workerProject` helper to `test/workers-project.mts`.
- Give each project its own file, holding its bindings and dummy secrets: `apps/api/vitest.workers.mts`,
  `apps/collector/vitest.workers.mts`, `packages/db/vitest.workers.mts`.
- Add `apps/loader/vitest.workers.mts` for the loader (its wrangler config, local D1 with every migration,
  R2 and its queue), with one smoke test that the loader's `queue()` handler acks an empty batch.
- The root config finds the project files by glob (`apps/*/vitest.workers.mts`,
  `packages/*/vitest.workers.mts`), so adding a package's Workers tests later means only a new project file in
  that package, with no edit to the root config.
- The same tests pass as before, plus the loader smoke test.

### 9. Dependencies for the E2B bridge

Add to `apps/api` `dependencies`, pinned to exact current versions: `e2b` (the E2B JS SDK) and `aws4fetch`
(signs R2 presigned URLs in a Worker). Nothing imports them yet. Also add `"@ti/core": "workspace:*"` to
`packages/db` `dependencies`, which `write.ts` needs. This branch owns `pnpm-lock.yaml`.

## Not in scope

- Any behaviour: no pattern, linker, writer, job or route logic beyond the helpers named above.
- Migrations, Wrangler configs and `ci.yml`. The only deploy changes are the order in 7b and the three
  variables in 7c; the only `loops.json` change is the sensitive paths in 7a.
- Changes to `apps/api/src/routes/*`, `apps/collector/src/*` and `e2b/`: the features own them. The only
  change to `apps/loader` is the one import in section 1.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process; `pnpm test:workers` still passes.
2. `@ti/core/inbox`, `@ti/core/r2-keys`, `@ti/core/control`, `@ti/core/sign`, `@ti/patterns/by-name`,
   `@ti/linker/link`, `@ti/db/write` and `@ti/db/tables` exist with the exported names and types above.
3. `sign.ts` tests cover every case in section 4. `r2-keys.ts`, `by-name.ts` and `databasesFromEnv` have tests.
4. `link()` and `writeRows()` throw `NotImplementedError`.
5. `LoadMessage` is declared only in `packages/core/src/inbox.ts`; `HeavyJobRequest` is
   `Omit<JobRequest, 'requestId' | 'cursor'>`.
6. `apps/api/package.json` lists `e2b` and `aws4fetch` at exact versions, and `packages/db` depends on
   `@ti/core`; no other dependency changes.
7. Each Workers test project lives in its own `vitest.workers.mts` file. `pnpm test:workers` runs the api,
   collector, db and loader projects, all green.
8. `git diff --stat main -- packages/db/migrations '**/wrangler.jsonc' .github/workflows/ci.yml` is empty.
   The only change under `scripts/` is the deploy order, and the only change to `deploy.yml` is the three
   production variables.
