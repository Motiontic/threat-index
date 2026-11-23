# apps/web

The public Threat Index site (`ti-web`): React Router 8 in framework mode, server-rendered on Cloudflare Workers
through `@cloudflare/vite-plugin`. Plan: `docs/IMPLEMENTATION_PLAN.md` §9.

Today every page renders **sample data from fixture files**. A band on every page says so, and the site is
`noindex`. Accounts (Clerk) and calls to `ti-api` come later; neither is wired yet.

## Layout

```
app/
  root.tsx            document, shell, root loader, error boundary
  routes.ts           / , /search, /e/:id, /index/:letter?, /sources, /account
  routes/             one file per page: loader + meta + component
  components/         shell (rail, top bar, drawer, footer) and ui (badge, chips, cards, tables, ...)
  data/               types.ts, data.server.ts (the only data seam), fixtures.server.ts, fixtures/*.json
  lib/                security.server.ts (CSP and headers), seo.tsx (meta, JSON-LD), format.ts, nonce.tsx
  styles/             tokens.css (every colour, radius, size), app.css (layout and components)
  entry.server.tsx    applies security headers and the CSP nonce to every response
workers/app.ts        the Worker entry
public/               robots.txt, favicon.svg, _headers
scripts/              smoke.mjs (workerd smoke check), deploy-web.mjs (build and deploy helpers)
test/                 Node unit tests, run by the root `pnpm test`
```

## Scripts

| Command                              | What it does                                                                                                                   |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm --filter @ti/web typecheck`    | `react-router typegen && tsc --noEmit`. Part of `pnpm build`.                                                                  |
| `pnpm --filter @ti/web build`        | `react-router build`: client and server bundles, plus `build/server/wrangler.json`.                                            |
| `pnpm --filter @ti/web test:workers` | Builds, starts `wrangler dev` on port 8710 (`PORT` overrides) and checks every route in `workerd`. Loop sandboxes and CI only. |

**Laptops run `pnpm build` only** (lint, typecheck, unit tests). The smoke check starts `wrangler dev`, which
belongs in loop sandboxes and CI. There is no `dev` script on purpose.

## The data-module swap point

Loaders call only `getData(request)` in `app/data/data.server.ts`, which returns
`{ home, search, entry, index, sources }`. To go live, change that function's body to calls through the `API`
service binding (`import { env } from 'cloudflare:workers'`) that forward the visitor's session, set `SAMPLE_DATA` to
`false`, and delete `app/data/fixtures/`. No route changes. The `.server` suffix keeps the module and the fixtures out
of the browser bundle (the smoke check fails if fixture text appears in `build/client`).

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
