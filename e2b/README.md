# e2b/

Heavy jobs run in E2B sandboxes. They cover anything too big for a Worker's 10 ms CPU limit: the first load, daily EPSS diff, big files, the nightly fold of receipts into Parquet, search-index builds and deep-history queries.

- `e2b.Dockerfile`: the sandbox template (Node 22 + DuckDB CLI, pinned and checksummed + the jobs bundle).
- `jobs/`: the job runner. It shares parsers with the Workers through `@ti/parsers`.
- `build-template.mjs`: builds the template (a person runs it, never a loop).

## How a job runs

1. The collector (or an ops script) calls `POST /internal/jobs` on ti-api, signed with `JOB_HMAC_SECRET` (`@ti/core/sign`). ti-api records the job in `ti_control.jobs`, creates a sandbox from the template (E2B SDK, `lib/e2b.ts`) and starts `node /app/run.mjs` with the Job JSON in `JOB_JSON`. The Job JSON holds a per-job key (`deriveJobKey`), never `JOB_HMAC_SECRET`, the E2B key or an R2 credential.
2. The job reads inputs with a **read-only**, bucket-scoped R2 token (DuckDB `httpfs`; not built yet).
3. To write, it asks ti-api for presigned R2 PUT URLs (`POST /internal/jobs/:id/upload-urls`), limited to `jobs/<id>/` and `inbox/<id>/`. The sandbox never holds a write key.
4. When done, it calls `POST /internal/jobs/:id/complete`. ti-api checks `inbox/<id>/manifest.json`, queues one `ti-load` message per chunk and kills the sandbox. A job that throws reports `{ ok: false, error }` and exits 1.
5. Hard timeout: 50 minutes. Active rows older than 55 minutes become `timed_out` on the next start.

Only the `echo` kind is enabled (`ENABLED_JOB_KINDS` in `apps/api/src/lib/e2b.ts`). The work that implements another kind adds it there.

## Launch path

The **SDK path** was chosen (e2b 2.64.0). Under workerd, with `fetch` stubbed, `apps/api/test/e2b-sdk.workers.test.ts` shows `Sandbox.create` reaching `POST https://api.e2b.app/v2/sandboxes` and `commands.run` reaching the envd host (`https://sandbox.e2b.app/process.Process/Start`), with no missing Node module, `node:http2`, `eval` or `new Function` error. `wrangler deploy --dry-run` bundles the API with the SDK. `CommandHandle.disconnect()` leaves the command running; command `timeoutMs: 0` disables its timeout. The REST path was not built.

## Checking the bridge on staging (after merge)

The real round trip has not been run; the loop has no E2B, Cloudflare or R2 credentials.

1. Set Wrangler secrets on `ti-api-staging` (`wrangler secret put <NAME> --env staging`): `JOB_HMAC_SECRET` (32+ random bytes, hex; the collector gets the same value), `E2B_API_KEY`, `R2_ACCOUNT_ID`, and `R2_ACCESS_KEY_ID` + `R2_SECRET_ACCESS_KEY` from an R2 token with Object Read & Write on `threat-index-staging` only.
2. `TI_API_URL_STAGING`, the `staging` environment var the deploy already uses, is the callback origin (a `pnpm preview` version calls back deployed staging, not itself).
3. `E2B_API_KEY=… node e2b/build-template.mjs threat-index-jobs-staging`
4. `JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs round-trip -- --api "$TI_API_URL_STAGING"` ends `complete`, and `wrangler r2 object get threat-index-staging/jobs/<id>/echo.json --remote` returns the log.

**Fallback:** if E2B is unavailable, the same jobs run locally with `pnpm --filter @ti/e2b-jobs job <name>`, using the same API callbacks.
