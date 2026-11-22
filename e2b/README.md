# e2b/

Heavy jobs run in E2B sandboxes. They cover anything too big for a Worker's 10 ms CPU limit: the first load, daily EPSS diff, big files, the nightly fold of receipts into Parquet, search-index builds and deep-history queries.

- `e2b.Dockerfile`: the sandbox template (Node 22 + DuckDB CLI + the jobs bundle).
- `jobs/`: the job runner. It shares parsers with the Workers through `@ti/parsers`.

## How a job runs

1. The collector (or the API) creates a sandbox from the template and starts `node /app/run.js` with the job description.
2. The job reads inputs with a **read-only**, bucket-scoped R2 token (DuckDB `httpfs`).
3. To write, it asks the API for presigned R2 upload URLs (`POST /internal/jobs/:id/upload-urls`, HMAC-signed), limited to the job's allowed prefixes. The sandbox never holds a write key.
4. When done, it calls `POST /internal/jobs/:id/complete` with a manifest of the `inbox/` chunks. The API queues them for the loader.
5. Hard timeout: 50 minutes.

**Fallback:** if E2B is unavailable, the same jobs run locally with `pnpm --filter @ti/e2b-jobs job <name>`, using the same API callbacks.
