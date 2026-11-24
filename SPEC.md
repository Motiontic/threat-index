# cache-namespace: staging and production never share cached API responses

## Why

Production (`ti-api`) and staging (`ti-api-staging`) run on the same Cloudflare zone (`*.intraface.workers.dev`),
so they share `caches.default`. Their cache keys do not name the environment:

- `apps/api/src/lib/cache.ts` (`cachedPublic`) keys every public route as `https://cache.internal${path}`.
- `apps/api/src/routes/search.ts` keys search as `canonicalUrl(url)`, and the web app calls the API through its
  service binding at the same origin in both environments (`https://ti-api.internal`, see
  `apps/web/app/data/api.server.ts`), so that key is the same too.

On 24 Nov 2026 production's `GET /v1/home` returned staging's counts (210,840 vulnerabilities, 1,793
exploited) while production's own database holds 220,406 and 661. Any public route (home, index pages,
breaches, incidents, techniques, sources, entries, search) can serve the other environment's data for up to its
TTL.

## What to build

1. One helper, for example `publicCacheKey(env, pathAndQuery)` in `apps/api/src/lib/cache.ts`, that builds
   `https://cache.internal/<namespace><pathAndQuery>`. The namespace identifies the deployment: use a value
   that differs between production and staging and is always set, such as the R2 bucket name the API is bound
   to (`R2_BUCKET_NAME`, `threat-index` vs `threat-index-staging`) or a new `TI_ENV` var set in both sections
   of `apps/api/wrangler.jsonc`. Never derive it from the request host (service-binding calls all use
   `ti-api.internal`).
2. Use the helper for every `caches.default` key in the API: `cachedPublic` and the search route (keep
   search's sorted query string). Grep for any other `caches.default` use and change it too.
3. Tests: two environments with different namespaces never read each other's entry for the same path and
   query (home and search); the same environment still hits its own cache; signed-in requests still bypass the
   cache.

## Not in scope

Everything else. No change to TTLs or to what is cached.

## Files this loop owns

`apps/api/src/lib/cache.ts`, `apps/api/src/routes/search.ts`, any other API file that keys `caches.default`,
`apps/api/wrangler.jsonc` (only if a var is added), `apps/api/src/lib/env.ts`, and tests under `apps/api/test/`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. The tests in section 3 pass.
3. `grep -rn "caches.default" apps/api/src` shows only keys built by the helper.
