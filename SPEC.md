# e2b-bridge: start E2B jobs from ti-api, let sandboxes upload and complete, round-trip an echo job

## Why

Heavy work (first loads, the EPSS diff, big files) runs in E2B sandboxes. Nothing starts one yet or lets it hand
results back; the callback routes are `501` stubs behind an HMAC of the job id that never expires.

This change builds the bridge and proves it with a dummy `echo` job: ti-api starts a job, records it in
`ti_control.jobs` and launches a sandbox; the sandbox gets presigned R2 PUT URLs inside its own prefixes, uploads and
reports completion; ti-api checks the manifest, queues one `ti-load` message per chunk and kills the sandbox. Built
at the same time elsewhere: the collector calls `POST /internal/jobs` over a service binding; the loader consumes
`LOAD`. The build sandbox has no E2B, Cloudflare or R2 credentials and tests must stay offline, so all of this is
tested with fakes; the real round trip is checked on staging after merge (§9).

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/internal-jobs.ts` | Middleware on `/internal/jobs/:id/*` accepts `x-job-signature` = `HMAC(JOB_HMAC_SECRET, id)` (`verifyHmac`): no expiry, not bound to method, path or body. `upload-urls` and `complete` return `501`. No route starts a job or reads one |
| `apps/api/src/lib/env.ts` | `DB_VULNS`, `DB_ADVISORIES`, `DB_USERS`, `BUCKET`, Clerk, Resend and unsubscribe secrets, `JOB_HMAC_SECRET`. No `DB_CONTROL`, `LOAD`, E2B or R2 signing values |
| `apps/api/wrangler.jsonc` | `nodejs_compat`, date `2026-11-01`; six D1 databases, `BUCKET`, `SETTINGS`, `LOAD` producer (`ti-load`, `ti-load-staging`). The comment lists `JOB_HMAC_SECRET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `E2B_API_KEY` as secrets. No template, bucket-name, account or API-origin value |
| `ti_control.jobs` | `id` PK, `kind`, `source_id`, `status`, `sandbox_id`, `created_at`, `finished_at`, `manifest_key`, `error`; `WITHOUT ROWID`, no secondary index, nowhere to store a request's `reason` or `url` |
| `e2b/jobs/src` | 7 `JOB_KINDS`; `Job { id, kind, sourceId?, apiBase, hmac }`; `JobContext { log }`. `run.ts` reads argv or `JOB_JSON` and imports `./jobs/<kind>.ts`; all seven throw `NotImplementedError`. Nothing calls the API |
| `e2b/e2b.Dockerfile` | `node:22-bookworm-slim`, DuckDB CLI 1.3.2 with no checksum, `COPY jobs/dist/`, but nothing builds `jobs/dist`. The header says `e2b template build`, which E2B removed on 21 Sep 2026 (SDK 2.50, CLI 2.19.1) |
| From the seams change | `@ti/core/sign` (`signRequest`, `verifyRequest`, `deriveJobKey`, `x-ti-*` headers, 300 s skew), `@ti/core/inbox` (`InboxManifest`, `LoadMessage`, `MAX_ROWS_PER_CHUNK`, `inboxChunkKey`, `inboxManifestKey`), `@ti/core/control` (`JOB_STATUSES`, `JobRequest`), `@ti/core/r2-keys` (`jobPrefix`), exact `e2b` and `aws4fetch` in `apps/api/package.json`, `apps/api/vitest.workers.mts` |
| Elsewhere | No ULID helper in any package. `apps/api/test/api.workers.test.ts` expects `401` from `complete` with no header and with `x-job-signature: abc`; it must pass unchanged |

## What to build

### 1. Check the SDK under workerd, then pick one launch path

Plan §6 marks "the E2B SDK runs in a Worker" as unverified; E2B's changelog (docs.e2b.dev/changelog, 27 Jul 2026)
says only that it "now imports cleanly under Cloudflare Workers". Before writing the launcher:

1. `apps/api/test/e2b-sdk.workers.test.ts` stubs `globalThis.fetch` (`vi.spyOn`, canned JSON), then runs `await
   import('e2b')`, `Sandbox.create(template, { apiKey, timeoutMs })` and `commands.run('true', { background: true,
   timeoutMs: 0 })`. Pass: create reaches the stub as `POST https://api.e2b.app/v2/sandboxes` and the command
   reaches the envd host, with no error from a missing Node module, `node:http2`, `eval` or `new Function` (a
   rejection caused by the canned reply is fine). If HTTP/2 fails, retry with `httpVersion: '1.1'`.
2. `wrangler deploy --dry-run --outdir <tmp> --env staging` bundles the api with the SDK; record the size.
3. The installed SDK confirms `CommandHandle.disconnect()` leaves the command running and what `timeoutMs: 0` means.

All pass: **SDK path**. Any fails: **REST path**; drop the SDK test, keep its output in PROOF.md. Build one path
only; record the choice, SDK version and evidence atop `lib/e2b.ts` and in `e2b/README.md`.

### 2. Launcher: `apps/api/src/lib/e2b.ts`

```ts
export const JOB_TIMEOUT_MS = 50 * 60 * 1000; // hard limit; E2B Hobby sandboxes live at most 1 h
export const STALE_AFTER_MS = 55 * 60 * 1000; // active rows older than this become timed_out
export const MAX_ACTIVE_JOBS = 5;
export type ApiJobKind = JobRequest['kind'] | 'echo'; // `echo` exists only in the API and the sandbox
export interface SandboxJob { id: string; kind: ApiJobKind; sourceId?: string; url?: string; apiBase: string; hmac: string }
export interface LaunchedSandbox { sandboxId: string; start(job: SandboxJob): Promise<void> }
export interface JobLauncher {
  create(opts: { timeoutMs: number; metadata: Record<string, string> }): Promise<LaunchedSandbox>;
  kill(sandboxId: string): Promise<void>; // resolves if the sandbox is gone or unknown
}
export function launcherFromEnv(env: Bindings): JobLauncher | null; // null if E2B_API_KEY, E2B_TEMPLATE or API_BASE is missing or bad
export function newJobId(now?: Date): string; // ULID: 26 Crockford base32 characters, time-sortable
export function parseManifest(text: string, jobId: string, kind: ApiJobKind): { manifest: InboxManifest } | { error: string };
```

- Two phases: the route records `running` and the sandbox id before the job starts, so a fast job never calls back
  while its row says `starting`. `SandboxJob` mirrors `Job` in `e2b/jobs/src/types.ts`.
- **SDK:** `Sandbox.create(E2B_TEMPLATE, { apiKey, timeoutMs, metadata, requestTimeoutMs: 30_000 })`; start with
  `commands.run('node /app/run.mjs', { background: true, envs: { JOB_JSON }, cwd: '/app', timeoutMs: 0 })` then
  `handle.disconnect()`; kill with `Sandbox.kill(id, { apiKey })`. Load it with `await import('e2b')` inside the
  launcher, so the SDK never runs at Worker start-up or on routes that don't launch.
- **REST:** `POST https://api.e2b.app/v2/sandboxes` (`X-API-Key`; `{ templateID, timeout: 3000, metadata, autoPause:
  false }`) returns `sandboxID` and `domain`; start by POSTing the Job JSON to the job server (§5) at
  `https://8080-<sandboxID>.<domain>/job`, retried up to 15 s; kill with `DELETE /sandboxes/<sandboxID>` (404 = gone).
  Check names in the SDK's `NewSandboxV2` type and host format in `connectionConfig.ts` (some regions use
  `sandbox.<domain>` since SDK 2.59). If create returns a `trafficAccessToken`, close public traffic and send it.
- The Job JSON never goes into sandbox `envs` or `metadata` (`{ jobId, kind }`). `API_BASE` must be an `https:`
  origin with path `/` (`http:` only for `localhost`). E2B calls time out within 30 s; their errors are cut to status
  and a short message before a log or `jobs.error`, never including the API key.

### 3. Presigned uploads: `apps/api/src/lib/presign.ts`

```ts
export const UPLOAD_URL_TTL_SECONDS = 600;
export const MAX_UPLOAD_URLS = 50;
export interface R2SigningConfig { accountId: string; bucket: string; accessKeyId: string; secretAccessKey: string }
export function r2SigningConfig(env: Bindings): R2SigningConfig | null; // null if any value is missing or malformed
export function allowedPrefixes(kind: ApiJobKind, jobId: string): string[];
export function uploadKeyError(key: string, prefixes: string[]): string | null; // reason, or null if allowed
export function presignPut(cfg: R2SigningConfig, key: string, ttlSeconds?: number): Promise<string>;
```

- Follow Cloudflare's `aws4fetch` example (developers.cloudflare.com/r2/api/s3/presigned-urls/): an `AwsClient`
  with `service: 's3'`, `region: 'auto'` signs `PUT https://<accountId>.r2.cloudflarestorage.com/<bucket>/<key>
  ?X-Amz-Expires=<ttl>` with `{ aws: { signQuery: true } }`. The URLs are bearer tokens: never log one. TTL 1–3600 s.
- `accountId` must be 32 lowercase hex characters and `bucket` a valid bucket name. Prefixes for every kind today:
  `jobPrefix(id)` and `inbox/<id>/`; jobs that later write `lake/` or `lookup/` add theirs here.
- `uploadKeyError` rejects: empty or over 256 characters; characters outside `[A-Za-z0-9._/-]`; a leading `/`; an
  empty, `.` or `..` segment; a bare prefix; anything outside the prefixes (`inbox/<otherId>/x`, `raw/x`, `jobs/<id>x/y`).

### 4. Routes: `apps/api/src/routes/internal-jobs.ts`

Export `createInternalJobsRoute(deps?: { launcher?: (env: Bindings) => JobLauncher | null; now?: () => Date;
newId?: () => string; enabledKinds?: readonly ApiJobKind[] })` and keep `export default createInternalJobsRoute()`;
`src/index.ts` does not change.

- Keys: `POST /internal/jobs` and `GET /internal/jobs/:id` (collector, ops script) use `JOB_HMAC_SECRET`;
  `POST /internal/jobs/:id/upload-urls` and `…/complete` (sandbox) use `deriveJobKey(JOB_HMAC_SECRET, id)`.
- Order: body size (`content-length` and the text read, at most 16 KiB, else `413`), then the signature, then the
  rest. Signature: `verifyRequest(key, { method, path: new URL(c.req.url).pathname, timestamp, signature, body })`
  with the `@ti/core/sign` headers, else `401 {"error":"invalid_signature"}`. An unset `JOB_HMAC_SECRET` fails
  closed and never reaches `deriveJobKey`. Then `:id` must match `JOB_ID = /^[0-9A-HJKMNP-TV-Z]{26}(-[0-9]{1,5})?$/`
  (a ULID, or a collector `requestId` of the form `<runId>-<step>`), else `400`.
- Errors are `{ "error": "<code>" }`. Zod parses bodies; the `JobRequest` schema `satisfies z.ZodType<JobRequest>`.
  D1 access is prepared SQL on `DB_CONTROL`. Logs carry job id, kind, status and sandbox id only.

**Start.** Body: a `JobRequest` (`requestId` matching `JOB_ID`, `reason` ≤ 200 characters, optional `https:`
`url` ≤ 2,048, optional `cursor`), or `{ kind: 'echo', reason }`. `echo` is API-side only: `JobRequest` stays
unchanged and the collector never sends it.

1. `kind` must be in `ENABLED_JOB_KINDS` (in `e2b.ts`, today `['echo']`), else `501 job_kind_not_ready`. The
   `first-load`, `epss-diff` and `big-file` jobs are still stubs; the work that implements each one adds its kind
   here, so no sandbox starts only to fail.
2. A non-echo `sourceId` must be in `SOURCE_BY_ID` (`400 unknown_source`) and pass `canIngest(source.licence)`
   (`403 source_not_ingestible`). KV overrides aren't read here, so this fails closed.
3. `launcherFromEnv` null: `503 e2b_not_configured`, no row.
4. Active rows (`queued`, `starting`, `running`) older than `STALE_AFTER_MS` become `timed_out` (`RETURNING`);
   their sandboxes are killed in `waitUntil`.
5. The job id is the request's `requestId`, or `newJobId()` for `echo`. A row with that id already exists, in any
   status: `200 {"jobId":…,"status":…,"existing":true}`, so a redelivered or replayed start is a no-op. Otherwise
   one `INSERT … SELECT … WHERE` adds the row as `starting` only if no active row has the same `kind` and
   `source_id` (`IS`) and fewer than `MAX_ACTIVE_JOBS` are active. Same kind and source active: `200` with that
   job's id and `existing: true`. Too many: `429 too_many_jobs`.
6. Write the request (with its `cursor`, if any) to `jobs/<id>/request.json` through the `BUCKET` binding.
7. `create({ timeoutMs: JOB_TIMEOUT_MS, metadata })`; `UPDATE … SET status='running', sandbox_id=? WHERE id=? AND
   status='starting'`; `start()` with `hmac = await deriveJobKey(JOB_HMAC_SECRET, id)` and `apiBase = API_BASE`.
8. `201 {"jobId":…,"status":"running"}`. If `create` or `start` throws: row `failed` with a short error, sandbox
   killed if it exists, `502 {"error":"launch_failed","jobId":…}`.

Callers treat `429`, `502` and `503` as retryable and every other `4xx` and `501` as permanent.

**Status.** `200 { jobId, kind, sourceId, status, sandboxId, createdAt, finishedAt, manifestKey, error }`, or `404`.

**Upload URLs.** Body `{ keys }`, 1 to `MAX_UPLOAD_URLS`. Unknown job `404`; not `running` `409 job_not_running`;
any bad key `400 {"error":"invalid_key","key":…}` and no URLs at all; no signing config `503 r2_not_configured`.
Else `200 { expiresInSeconds, urls: [{ key, url }] }` in request order.

**Complete.** Body `{ ok: true }` or `{ ok: false, error }` (stored cut to 1,000 characters).
- Unknown `404`. Already `complete` or `failed`: `200 { jobId, status, queued: 0, repeated: true }`, nothing
  re-sent. `queued`, `starting` or `timed_out`: `409 job_not_running`. `ok: false`: row `failed`, manifest unread.
- `ok: true` reads `inboxManifestKey(id)`. `parseManifest` rejects a missing object, over 1 MiB, bad JSON, `jobId`
  ≠ id, over 5,000 chunks, a key that isn't `inboxChunkKey(id, n)`, a repeated key, and `rows` outside 1 to
  `MAX_ROWS_PER_CHUNK`. Chunk refs carry no priority. Invalid: row `failed` (`invalid_manifest: <reason>`),
  `400`, nothing sent.
- One `LoadMessage` per chunk on `LOAD` in manifest order, `sendBatch` slices of ≤ 100 (Queues limit). Each
  message's `priority` comes from the job's kind (`first-load` → `'first-load'`, every other kind → `'steady'`),
  never from the manifest, so a sandbox can't dodge the daily cap.
- If `jobs/<id>/request.json` holds a `cursor`, upsert it into `cursors` for the job's source (`updated_at` = now)
  only now, after every message is sent. A failed job never moves a source's cursor.
- Then `UPDATE … SET status='complete', finished_at, manifest_key WHERE id=? AND status='running'`. If a send throws,
  reply `503`, job still `running`, for the sandbox to retry; queues are at-least-once, and the loader acks a chunk
  it already loaded and deleted. `chunks: []` is valid. Reply `200 { jobId, status: 'complete', queued: n }`.
- Whenever a job ends here, kill its sandbox in `waitUntil` and log a failed kill.

### 5. Sandbox side: `e2b/jobs/`

- `src/types.ts`: add `'echo'` to `JOB_KINDS`, `url?: string` to `Job`, `api: JobApi` to `JobContext`.
- New `src/client.ts`: `createJobApi(job, deps?: { fetch?, now? }): JobApi` with `uploadUrls(keys)`,
  `upload(files: { key, body, contentType }[])` and `complete(result)`. It signs with `signRequest(job.hmac,
  'POST', '/internal/jobs/<id>/<route>', …)` and a fresh timestamp per attempt, retries network errors and `5xx`
  up to 3 times, never a `4xx`. `upload` asks for URLs 50 at a time; a non-2xx PUT or a missing key throws.
- `src/run.ts`: export `main(job, deps)`, run it only when executed. Read `JOB_JSON` (or argv), then `delete
  process.env.JOB_JSON` so child processes never inherit the key. After `run()`, `complete({ ok: true })`; on a
  throw, `complete({ ok: false, error })` and exit 1, so stubs fail fast and their sandboxes are killed.
- New `src/jobs/echo.ts`: one `upload` of `jobs/<id>/echo.json` (`{ id, kind, at, node: process.version }`, nothing
  from the environment) and `inboxManifestKey(id)` holding `{ jobId: id, createdAt, chunks: [] }`.
- REST path only, new `src/server.ts`: on port 8080, takes one `POST /job` (≤ 16 KiB), replies `202`, stops
  listening and runs `main`; anything else `404`, a second job `409`.
- New `build.mjs`, scripts `bundle` and `round-trip`: bundle `src/run.ts` (plus `server.ts`) and its `@ti/*` imports
  into `dist/*.mjs` (`platform: 'node'`, `target: 'node22'`, ESM). No dependency may be added, so load `esbuild`
  through wrangler's (`createRequire` from `wrangler/package.json`). If `./jobs/${kind}.ts` won't bundle, use a map.

### 6. Template and ops scripts

- `e2b/e2b.Dockerfile`: `node:22-bookworm-slim`, the current DuckDB CLI pinned and checked with `sha256sum -c`
  before unzipping, `WORKDIR /app`, `COPY jobs/dist/ /app/`, a corrected header.
- New `e2b/build-template.mjs <name>`, run by a person, never the loop: exits if `TI_LOOP_SANDBOX=1` or
  `E2B_API_KEY` is unset, never prints the key, runs the bundle, then `Template({ fileContextPath: 'e2b' })
  .fromDockerfile(…)` (REST: `.setStartCmd('node /app/server.mjs', waitForPort(8080))`) and `Template.build(
  template, name, { cpuCount: 2, memoryMB: 4096 })`, loading `e2b` from `apps/api`. Check names in its types.
- New `e2b/jobs/src/round-trip.ts` (`pnpm --filter @ti/e2b-jobs round-trip -- --api <origin>`): reads
  `JOB_HMAC_SECRET` from the environment only, starts `{ kind: 'echo', reason: 'round-trip check' }`, polls the
  status route every 5 s for up to 10 minutes, exits 0 only on `complete`, prints the job id and status only. If
  `@ti/core` won't load under Node's type stripping, run it from the bundle.

### 7. Bindings and config

- `lib/env.ts`: `DB_CONTROL`, `LOAD: Queue<LoadMessage>`, vars `API_BASE`, `E2B_TEMPLATE`, `R2_BUCKET_NAME`, and
  secrets `E2B_API_KEY`, `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` as `string | undefined`.
- `wrangler.jsonc` vars. Production: `API_BASE: "${TI_API_URL}"`, `E2B_TEMPLATE: "threat-index-jobs"`,
  `R2_BUCKET_NAME: "threat-index"`. Staging (vars don't inherit): `"${TI_API_URL_STAGING}"`,
  `"threat-index-jobs-staging"`, `"threat-index-staging"`, plus `ADMIN_USER_IDS`. The deploy workflow already sets
  both placeholders. `R2_ACCOUNT_ID` is a secret, not a var, so the account ID stays out of config and deploy logs.
- `.dev.vars.example`: `R2_ACCOUNT_ID=` 32 zeros (a well-formed placeholder). `apps/api/vitest.workers.mts`: dummy
  `E2B_API_KEY`, `R2_ACCOUNT_ID` (32 hex), `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`.

### 8. Tests

- Node, `apps/api/test/e2b-bridge.test.ts` (never loads the SDK): `newJobId`; each `uploadKeyError`, `parseManifest`
  and `launcherFromEnv` rule; `presignPut` host, path, `X-Amz-Expires`, signature present, secret absent, TTL clamped.
- Node, `e2b/jobs/src/*.test.ts`, a fake `fetch` as the API: signatures pass `verifyRequest(await deriveJobKey(…))`;
  retry on `503`, none on `4xx`; echo's two objects, no `hmac` in the log; `main` completes `ok: true`, or `ok:
  false` and exit 1 for a stub; round trip stops on `complete`/`failed`; REST: the server refuses a second job.
- Workers, `apps/api/test/internal-jobs.workers.test.ts`, with a fake launcher, a recording `LOAD` (`{ ...env, LOAD:
  fake }`), a `waitUntil` that collects promises and objects put straight into local R2. One case per status code
  and rule in §4, including: `401` for unsigned, stale, changed-body and wrong-key calls (ops secret on a job route,
  job A's key on job B, a job key on start or status) and an unset secret; the Job JSON holds the derived `hmac` and
  no secret, E2B key or R2 value, with `timeoutMs` ≤ 50 min; a 56-minute-old row becomes `timed_out`; 250 chunks go
  out as 100, 100, 50; a repeated `complete` sends nothing; a kill whenever a job ends; a `first-load` request
  while only `echo` is enabled → `501`; with `enabledKinds` injected through the route's `deps`: the same
  `requestId` twice → one row, `existing: true`; a `first-load` job's messages are all `first-load` and a
  `big-file` job's all `steady`, whatever the manifest says; the request's `cursor` reaches `cursors` only after
  a successful `complete`, never after `ok: false`; and a round trip in which the
  test acts as the sandbox with the captured Job JSON. No captured `console` output has `X-Amz-Signature`, a key or
  the secret.

### 9. Checked on staging after merge, not in the loop

1. Wrangler secrets on `ti-api-staging` (`wrangler secret put <NAME> --env staging`): `JOB_HMAC_SECRET` (32+
   random bytes, hex; the collector gets the same value), `E2B_API_KEY`, `R2_ACCOUNT_ID`, and `R2_ACCESS_KEY_ID` +
   `R2_SECRET_ACCESS_KEY` from an R2 token with Object Read & Write on `threat-index-staging` only.
2. `TI_API_URL_STAGING`, the `staging` environment var the deploy already uses, is the callback origin (a `pnpm
   preview` version calls back deployed staging, not itself).
3. `E2B_API_KEY=… node e2b/build-template.mjs threat-index-jobs-staging`.
4. `JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs round-trip -- --api "$TI_API_URL_STAGING"` ends `complete`, and
   `wrangler r2 object get threat-index-staging/jobs/<id>/echo.json --remote` returns the log.

## Not in scope

- Real job bodies, `lake/` and `lookup/` prefixes, the read-only R2 token for DuckDB; the second launch path.
- The collector's call to `POST /internal/jobs`; the loader; `jobs/` retention; a watchdog beyond the stale sweep.
- Migrations or columns (`reason` is logged, `url` passed on); dependencies or `pnpm-lock.yaml`; `src/index.ts`,
  `lib/auth.ts`, `scripts/`, `.github/` and the seams files.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process.
2. `pnpm test:workers` passes with the tests in §8; the existing api tests pass unchanged.
3. The launch path follows §1, with its evidence in PROOF.md, atop `lib/e2b.ts` and in `e2b/README.md`.
4. `rg x-job-signature apps/api/src` finds nothing; internal routes verify only through `@ti/core/sign`. Tests show
   the Job JSON holds no `JOB_HMAC_SECRET`, E2B key or R2 credential, and no log holds a presigned URL or a key.
5. `git diff main -- pnpm-lock.yaml` is empty; no `package.json` changes its dependencies; `git diff --name-only
   main` lists only `e2b/**`, `apps/api/src/routes/internal-jobs.ts`, `apps/api/src/lib/{e2b,presign,env}.ts`,
   `apps/api/wrangler.jsonc`, `apps/api/.dev.vars.example`, `apps/api/vitest.workers.mts`, new `apps/api/test/` files.
6. `pnpm --filter @ti/e2b-jobs bundle` writes `e2b/jobs/dist/run.mjs`; a bad `JOB_JSON` exits non-zero clearly.
7. Proof saved: `pnpm build` and `pnpm test:workers` output, and one `wrangler dev --env staging` run of the api on
   port 8700, `.dev.vars` from the example with dummy values and an **empty** `E2B_API_KEY` (nothing calls E2B).
   Curl output for: all four routes unsigned (`401`); signed start (`503 e2b_not_configured`); with a `running` row
   seeded by `wrangler d1 execute … --local` and an empty manifest by `wrangler r2 object put … --local`, signed
   `upload-urls` (`200`; show the URL host and query names, not the signature), a bad key (`400`), `complete`
   (`200`, then `200` with `repeated`) and status (`complete`). Sign with an uncommitted throwaway script using
   `@ti/core/sign`. Stop the server afterwards.
8. `e2b/README.md` has the §9 steps, and the PR says the real round trip has not run yet.
