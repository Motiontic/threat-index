# apps/web

The public Threat Index site (`ti-web`): React Router 8 in framework mode, server-rendered on Cloudflare Workers
through `@cloudflare/vite-plugin`. Plan: `docs/IMPLEMENTATION_PLAN.md` §9.

Pages read live records from `ti-api` through the `API` service binding (`DATA_SOURCE=api`, set in
`wrangler.jsonc`). With `DATA_SOURCE=fixtures`, or when the binding is missing, the site serves hand-written fixtures
through an in-process fake of the same routes, shows a "sample data" band and sends `X-Robots-Tag: noindex`.
To run locally without ti-api: `wrangler dev -c build/server/wrangler.json --var DATA_SOURCE:fixtures` (loop sandboxes
only). Sign-in (Clerk) is not wired yet; locked tabs stay locked.

## Layout

```
app/
  root.tsx            document, shell, root loader, error boundary
  routes.ts           / , /search, /e/:id, /index/:letter?, /sources, /account
  routes/             one file per page: loader + meta + component
  components/         shell (rail, top bar, drawer, footer) and ui (badge, chips, cards, tables, ...)
  data/               data.server.ts (the only reader of env.API), api.server.ts (the only fetch), guards.ts,
                      fixture-api.server.ts (fake ti-api), mode.server.ts, fixtures/*.json
  lib/                security.server.ts (CSP and headers), seo.tsx (meta, JSON-LD), format.ts, nonce.tsx
  styles/             tokens.css (every colour, radius, size), app.css (layout and components)
  entry.server.tsx    applies security headers and the CSP nonce to every response
workers/app.ts        the Worker entry
public/               robots.txt, favicon.svg, _headers
scripts/              smoke.mjs (workerd smoke check, --mode fixtures|api), stub-api/ (stand-in ti-api), deploy-web.mjs
test/                 Node unit tests, run by the root `pnpm test`
```

## Scripts

| Command                              | What it does                                                                                                                   |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm --filter @ti/web typecheck`    | `react-router typegen && tsc --noEmit`. Part of `pnpm build`.                                                                  |
| `pnpm --filter @ti/web build`        | `react-router build`: client and server bundles, plus `build/server/wrangler.json`.                                            |
| `pnpm --filter @ti/web test:workers` | Builds, then smoke-checks every route in `workerd` in fixtures mode (port 8710) and api mode against `scripts/stub-api` (port 8711). Loop sandboxes and CI only. |

**Laptops run `pnpm build` only** (lint, typecheck, unit tests). The smoke check starts `wrangler dev`, which
belongs in loop sandboxes and CI. There is no `dev` script on purpose.

## The data seam

Loaders call only `getData(request)` in `app/data/data.server.ts`, the one file that reads `env.API`. It builds a
client (`api.server.ts`, the one file that calls `fetch`) over the binding in api mode or over `fixtureApi` in fixtures
mode. Requests are previews: no visitor header is forwarded and query strings are rebuilt from validated values.
Responses pass hand-written guards (`guards.ts`) that copy only the fields pages use. An unavailable API renders the
502 page. `/sitemap.xml` passes through ti-api's `/v1/sitemap.xml` when it exists (it does not yet, so production
answers 404 until the API adds it). `.server` keeps these modules and the fixtures out of the browser bundle.

## Environments are chosen at build time

`wrangler.jsonc` has production at the top level and `env.staging` for staging, but the plugin reads it during the
build and writes one flattened config:

```
pnpm --filter @ti/web build                          # ti-web          -> API = ti-api
CLOUDFLARE_ENV=staging pnpm --filter @ti/web build   # ti-web-staging  -> API = ti-api-staging
```

The build writes `build/server/wrangler.json` and a redirect to it at `.wrangler/deploy/config.json`. Deploy with
`wrangler deploy -c build/server/wrangler.json`, **never** with `--env`. `scripts/deploy.mjs` does this through
`scripts/deploy-web.mjs`: `buildWeb(target)` builds, `builtWebConfig(target)` refuses a build for the wrong
environment, `checkWeb(url)` waits for `GET /` to return HTML. The web app deploys last because its service binding
needs `ti-api` to exist.

## Security

`app/lib/security.server.ts` builds the headers. Every document response gets a fresh nonce CSP
(`script-src 'self' 'nonce-…'`, no inline styles, no `data:` URLs), `nosniff`, `X-Frame-Options: DENY` and more; `.data`
responses get the same minus the CSP. So no `style` attributes anywhere, and the only forms are GET search forms.
`vite dev` (not run in loops) adds `'unsafe-eval'` to `script-src` and `ws:` / `http:` to `connect-src` for hot reload.
Sign-in will add Clerk's origins.
