# e2b/

Heavy jobs run in E2B sandboxes. They cover anything too big for a Worker's 10 ms CPU limit: the first load, daily EPSS diff, big files, the nightly fold of receipts into Parquet, search-index builds and deep-history queries.

- `e2b.Dockerfile`: the sandbox template (Node 22 + DuckDB CLI, pinned and checksummed + the jobs bundle).
- `jobs/`: the job runner. It shares parsers with the Workers through `@ti/parsers`.
- `build-template.mjs`: builds the template (a person runs it, never a loop).

## How a job runs

1. The collector (or an ops script) calls `POST /internal/jobs` on ti-api, signed with `JOB_HMAC_SECRET` (`@ti/core/sign`). ti-api records the job in `ti_control.jobs`, creates a sandbox from the template (E2B SDK, `lib/e2b.ts`) and starts `node /app/run.mjs` with the Job JSON in `JOB_JSON`. The Job JSON holds a per-job key (`deriveJobKey`), never `JOB_HMAC_SECRET`, the E2B key or an R2 credential.
2. The job reads inputs with a **read-only**, bucket-scoped R2 token (DuckDB `httpfs`; not built yet).
3. To read and write, it calls the sandbox data routes on ti-api (below). The sandbox never holds an R2 key. `POST /internal/jobs/:id/upload-urls` (presigned PUTs, `503 r2_not_configured` without R2 keys) still exists but the client no longer needs it.
4. When done, it calls `POST /internal/jobs/:id/complete`. ti-api checks `inbox/<id>/manifest.json`, queues one `ti-load` message per chunk and kills the sandbox. A job that throws reports `{ ok: false, error }` and exits 1.
5. Hard timeout: 50 minutes. Active rows older than 55 minutes become `timed_out` on the next start.

Enabled kinds (`ENABLED_JOB_KINDS` in `apps/api/src/lib/e2b.ts`): `echo`, `first-load`, `epss-diff`, `nightly-fold`, `search-index`. `big-file`, `compaction` and `deep-query` are not built. `nightly-fold` and `search-index` are global (no source; optional `day`). No cron starts any of these yet.

## Sandbox data routes

All use the per-job key (`deriveJobKey`), need a `running` job, and sign `METHOD\npath\ntimestamp\nhex(sha256(body))` with headers `x-ti-timestamp` and `x-ti-signature` (`@ti/core/sign`). **The signed path is `pathname + search` exactly as sent**, so the query is covered; a GET signs the empty body; a PUT signs its SHA-256 hex digest (the `x-ti-content-sha256` header) as the body string. A path containing `%` is refused.

| Route | What it does |
| ----- | ------------ |
| `PUT /internal/jobs/:id/objects/<key>` | Streams the body to R2 (`content-length` required, ≤ 50 MiB; R2 checks the digest). Keys: `jobs/<id>/`, `inbox/<id>/`, plus `lake/records/<source>/` (first-load), `lake/epss/epss/` (epss-diff), `lake/raw/` (nightly-fold), `lookup/{search,index,vuln,pkg}/` and `sitemap.xml` (search-index). `jobs/<id>/request.json` is reserved. |
| `GET /internal/jobs/:id/objects/<key>` | Streams an object under `raw/`, `lake/`, `lookup/`, `jobs/<id>/` or `inbox/<id>/`. 404 if missing. |
| `GET /internal/jobs/:id/list?prefix=&cursor=` | `{ objects: {key,size}[], cursor }`, ≤ 1,000 per page, prefix inside a read prefix. |
| `GET /internal/jobs/:id/rows/<vulns\|advisories\|signals>?after=&limit=` | Keyset-paged D1 rows `{ rows, next }`, limit 1–1,000 (default 500). Not for `echo`. |

Sandboxes get `SITE_ORIGIN` in their environment when ti-api has an optional `SITE_ORIGIN` var (an https origin).

## Starting a job on staging

```
export JOB_HMAC_SECRET=…   # the staging secret
API=$TI_API_URL_STAGING
pnpm --filter @ti/e2b-jobs start-job -- --api "$API" --kind first-load --source cisa-kev \
  --url https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
pnpm --filter @ti/e2b-jobs start-job -- --api "$API" --kind epss-diff --source epss
pnpm --filter @ti/e2b-jobs start-job -- --api "$API" --kind nightly-fold [--day YYYY-MM-DD]
```

Add `--no-wait` to return after the start. The script prints the job id and status only and exits 0 only when the job ends `complete`. `epss-diff` writes scores to `lake/` only; it does not update `vulns.epss*` in D1.

## Launch path

The **SDK path** was chosen (e2b 2.64.0). Under workerd, with `fetch` stubbed, `apps/api/test/e2b-sdk.workers.test.ts` shows `Sandbox.create` reaching `POST https://api.e2b.app/v2/sandboxes` and `commands.run` reaching the envd host (`https://sandbox.e2b.app/process.Process/Start`), with no missing Node module, `node:http2`, `eval` or `new Function` error. `wrangler deploy --dry-run` bundles the API with the SDK. `CommandHandle.disconnect()` leaves the command running; command `timeoutMs: 0` disables its timeout. The REST path was not built.

## Checking the bridge on staging (after merge)

The real round trip has not been run; the loop has no E2B, Cloudflare or R2 credentials.

1. Set Wrangler secrets on `ti-api-staging` (`wrangler secret put <NAME> --env staging`): `JOB_HMAC_SECRET` (32+ random bytes, hex; the collector gets the same value), `E2B_API_KEY`, `R2_ACCOUNT_ID`, and `R2_ACCESS_KEY_ID` + `R2_SECRET_ACCESS_KEY` from an R2 token with Object Read & Write on `threat-index-staging` only.
2. `TI_API_URL_STAGING`, the `staging` environment var the deploy already uses, is the callback origin (a `pnpm preview` version calls back deployed staging, not itself).
3. `E2B_API_KEY=… node e2b/build-template.mjs threat-index-jobs-staging`
4. `JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs round-trip -- --api "$TI_API_URL_STAGING"` ends `complete`, and `wrangler r2 object get threat-index-staging/jobs/<id>/echo.json --remote` returns the log.

**Fallback:** if E2B is unavailable, the same jobs run locally with `pnpm --filter @ti/e2b-jobs job <name>`, using the same API callbacks.
