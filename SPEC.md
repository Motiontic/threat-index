# web-shell: the public web app shell, server-rendered on Workers from sample data

## Why

`ti-web` is the public site (plan §9), but `apps/web` holds only a README and a placeholder `package.json`. This change
delivers the shell: framework setup, the Motiontic look, the layout, a route for every public page, security headers
and deploy wiring. Pages render **sample data from fixture files** through one data module; later work swaps that
module for `ti-api` calls over the `API` service binding and adds sign-in, and nothing else needs to move. Other
features are built alongside, so this one edits only `apps/web/**`, two root `package.json` scripts, `pnpm-lock.yaml`
(it is the only branch that changes it) and the web lines in `scripts/deploy.mjs`.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/web` | `README.md` and a `package.json` (`@ti/web`) with no scripts or dependencies. No source, no `wrangler.jsonc` |
| Root `package.json` | `build` = `lint` + `typecheck` + `test`; `typecheck` skips `@ti/web`; `test:workers` runs `vitest.workers.config.mts` |
| `pnpm-lock.yaml` | `wrangler` 4.166.0, `vite` 7.3.8 (through `vitest` 5.1.1), `typescript` 5.9.3, `react` 19.3.1 (through Clerk) |
| `scripts/deploy.mjs` | Deploys `loader`, `notify`, `api`, `collector` (the shared contract moved `api` before `collector`) with `wrangler deploy [--env staging] -c apps/<app>/wrangler.deploy.jsonc`, then checks `/v1/health` |
| `scripts/wrangler-config.mjs` | `APPS` = every `apps/*` with a `wrangler.jsonc`, so `web` joins as soon as it has one |
| `.github/workflows/` | `deploy.yml`: staging has `TI_APP_URL_STAGING`; the shared contract added `TI_APP_URL` to production. `ci.yml`: lint, typecheck, test, `test:workers`; nothing builds the web app |
| `apps/api` | `GET /v1/entries/:id` returns `{ access, entry, credits }`; visitors get `key`, `kind`, `title`, `summary`, `published`, `cvss`, `kev_added`. Search, index and sources routes are `501` stubs |
| Shared code | `NVD_NOTICE` (`@ti/core/licence`), `normaliseId` (`@ti/core/ids`), `SOURCES` (55) and `SOURCE_BY_ID` with `credit` lines (`@ti/sources/registry`) |
| `biome.json`, `vitest.config.ts` | Biome lints everything but `node_modules`, `.wrangler`, `dist` and named paths. Root Vitest runs every `*.test.ts(x)` except `*.workers.test.ts` |
| Other apps' `wrangler.jsonc` | Top level = production, `env.staging` = staging; `compatibility_date` `2026-11-01`, `nodejs_compat` |

The seams change merges first. Of these files it touches `pnpm-lock.yaml`, the deploy order and the production
variables in `deploy.yml`; this branch builds on that and doesn't edit `deploy.yml`.

## What to build

### 1. Framework and versions

React Router in framework mode on Workers through `@cloudflare/vite-plugin`, laid out as `create-cloudflare
--framework=react-router` generates it today: `workers/app.ts` passes each request to `createRequestHandler(() =>
import('virtual:react-router/server-build'), import.meta.env.MODE)`; `vite.config.ts` has `cloudflare({ viteEnvironment:
{ name: 'ssr' } })` and `reactRouter()`; `react-router.config.ts` has `ssr: true` and no `future` flags. Server code
reads bindings with `import { env } from 'cloudflare:workers'`.

**Use React Router 8, not 7.** The plan says v7, but v8 shipped in June 2026. It is v7 with the `v8_*` future flags
made defaults, Cloudflare's guide and `create-cloudflare` now set it up, and `@clerk/react-router` supports `^8.3.0`.

Pin exact versions (no `^`) in `apps/web/package.json`. Dependencies: `react-router` 8.5.2; `react`, `react-dom`
19.3.1 (already locked); `isbot` 5.2.3; `@fontsource-variable/geist` and `@fontsource-variable/geist-mono` 5.3.0
(self-hosted fonts); `@ti/core`, `@ti/sources` (`workspace:*`). Dev: `@react-router/dev` 8.5.2; `@cloudflare/vite-plugin`
1.70.1 (not the 2.0 release candidates, which stop reading `wrangler.jsonc`); `vite` 7.3.8 (what `vitest` uses, so the
tree keeps one Vite); `@types/react`, `@types/react-dom` 19.3.0. No Tailwind, no path-alias plugin. `wrangler` (4.166.0
meets the plugin's `^4.164.0`), `typescript` and `@cloudflare/workers-types` stay root dev dependencies. React Router 8
needs Node ≥ 22.22: set `engines.node` to `>=22.22.0` and record `node --version`. If a pin fails, change only that one
and say why. If a dependency needs an install script, stop and report it rather than edit `pnpm-workspace.yaml`.

### 2. Worker config and types

- `apps/web/wrangler.jsonc`, styled like the other apps, with no `${VAR}`: `name` `ti-web`, `main` `./workers/app.ts`,
  `compatibility_date` `2026-11-01`, `nodejs_compat`, observability on, `vars.TI_ENV` `"production"`, and
  `services: [{ "binding": "API", "service": "ti-api" }]` (for later; nothing calls it). `env.staging` points `API` at
  `ti-api-staging` and sets `TI_ENV` to `"staging"`; the worker becomes `ti-web-staging`.
- A comment explains that the environment is chosen **at build time** (`CLOUDFLARE_ENV=staging`). The build writes a
  flattened config (`build/server/wrangler.json`) and a redirect to it (`.wrangler/deploy/config.json`); `--env` is never
  passed to wrangler for this app. Confirm both paths after the first build. `vite.config.ts` sets
  `build.assetsInlineLimit: 0`, so no asset becomes a `data:` URL. `.gitignore`: `build/`, `.react-router/`.
- `app/env.d.ts` declares `Cloudflare.Env` by hand (`API: Fetcher`, `TI_ENV`). `tsconfig.json` extends the base with the
  DOM libraries, `jsx: "react-jsx"`, `@cloudflare/workers-types`, `vite/client` and `rootDirs` for `.react-router/types`.
  If DOM and Workers types clash past `skipLibCheck`, commit the template's `worker-configuration.d.ts` instead, check
  it in CI with `wrangler types --check`, and say so. `pnpm build` never runs `wrangler types`.

### 3. Data module and fixtures

- `app/data/types.ts` mirrors the API. `EntryPreview` = the API preview fields that apply (`key`, `title`, `summary`,
  `published`, `cvss`, `kev_added`) plus display fields for the API work to confirm: `type` (`vuln` | `breach` | `ai` |
  `mal` | `tech` | `term`), `subtitle`, `aliases`. `EntryResponse` = `{ access: 'preview', entry, credits }`.
- `app/data/data.server.ts`: `getData(request)` returns `{ home, search, entry, index, sources }`, and the module exports
  `SAMPLE_DATA = true`. Loaders call only this. Later its body becomes `env.API` calls that forward the session, with no
  route changes. The `.server` suffix keeps it and `fixtures.server.ts` (over `app/data/fixtures/*.json`, with a
  `README.md` saying they are hand-written samples) out of the browser bundle.
- `entry(id)`: `normaliseId`, then match the key or any alias; unknown → `null`. Only the fields above: no EPSS, exploit
  details, affected versions, fixes, timeline or receipts. `credits` = each cited source's `credit` line, plus
  `NVD_NOTICE` once when `nvd` is cited (the API's rule).
- `search({ q, type[], sig[], sort })`: case-insensitive match on key, aliases, title, subtitle, summary; exact key or
  alias first; unknown `type`/`sig` values (only `kev` exists) ignored; `q` cut to 200 characters; `sort` `rel` (default
  with `q`) or `new`; at most 20 results.
- `index(letter)`: buckets `a`–`z` and `0` (digit or symbol), with counts. `sources(status)`: the 55 `SOURCES` rows plus a
  sample last-success time (none for `wait`), filtered by licence status. `home()`: tile counts computed from the
  fixtures (no invented totals), latest KEV additions, latest example breaches, a "what changed" list.

About 15 fixture records, each summary in your own words (≤ 300 characters), never pasted source text. CVEs use these
real IDs and public facts:

| ID | Short title | Published | CVSS | Added to CISA KEV | Alias |
| -- | ----------- | --------- | ---- | ----------------- | ----- |
| CVE-2025-3248 | Langflow unauthenticated code execution | 2025-04-07 | 9.8 | 2025-05-05 | GHSA-c995-4fw3-j39m |
| CVE-2021-44228 | Log4Shell, Apache Log4j | 2021-12-10 | 10.0 | 2021-12-10 | GHSA-jfh8-c2jp-5v3q |
| CVE-2024-3094 | xz Utils backdoor | 2024-03-29 | 10.0 | no | |
| CVE-2023-34362 | MOVEit Transfer SQL injection | 2023-06-02 | 9.8 | 2023-06-02 | |
| CVE-2024-3400 | PAN-OS GlobalProtect command injection | 2024-04-12 | 10.0 | 2024-04-12 | |
| CVE-2024-6387 | regreSSHion, OpenSSH | 2024-07-01 | 8.1 | no | |

Add `T1190`, `T1195.002`, `CWE-306` and the terms `KEV` and `EPSS`. Breach, AI incident and malicious-package records are
invented: IDs start with `EXAMPLE-` and name only `Example Co.` / `example.com`. Cite only `on` or `ask` sources.

### 4. The look: tokens in one place

`app/styles/tokens.css` holds every colour, radius, shadow, font and type size as a CSS variable; no other file has a
colour literal. Dark applies under `prefers-color-scheme: dark` unless `<html data-theme="light">`, and always under
`data-theme="dark"`. Fonts: Geist 400–700 for text, Geist Mono for IDs, labels and numbers.

- Light / dark: canvas `#FAFAF8` / `#111110`; paper `#FFFFFF` / `#1A1A18`; ink `#121212` / `#F2F1EC`; ink-2 `#4A4A47` /
  `#BDBBB3`; ink-3 `#6B6A64` / `#9A988F`; line `#E6E4DE` / `#2C2B28`; line-2 `#D6D3CB` / `#3A3935`; neutral fill
  `#EDEBE6` / `#242320`; tile `#EEEFFC` / `#22243F`; tile-ink `#2B2F6B` / `#C9CCF7`; accent `#EF7D45` / `#F2905E`;
  accent-soft `#FDEBE1` / `#3A2418`; accent-ink `#B4501C` / `#F2905E`; ok `#2F7A55` / `#5DB487`; warn `#9A5F0A` /
  `#E0A040`; bad `#C23B1F` / `#F0664A`. Shadow `0 1px 2px rgb(18 18 18 / 5%)` in light, none in dark.
- Accent `#EF7D45` is 2.6:1 on canvas: use it for fills, borders, the brand dot and meters only. Accent text and the
  focus ring use accent-ink (4.9:1); ink-3, ok, warn and bad are dark enough for 4.5:1 text. The PR lists every ratio.
- Type: body 14px/1.5; muted 12px; mono labels 11px uppercase, 0.08em tracking; card titles 16px/600; page headings
  24px/600; entry title `clamp(24px, 3vw, 32px)`; home headline `clamp(28px, 4.2vw, 44px)`, 600, -0.035em; tile
  numbers 24px tabular. Radii 8px (nav, small controls), 10px (inputs, buttons), 12px (cards, panels, tables, tiles),
  14px (gate card), 99px (pills). Spacing 4, 6, 8, 10, 12, 16, 22, 30px.
- `:focus-visible`: 2px accent-ink outline, offset 2px. No `style` attributes anywhere (the CSP blocks them).

### 5. Layout and components

- **Sample-data band** on top while `SAMPLE_DATA` is true: ink, 12px, centred, "Preview with sample data. Live records
  arrive when the site is connected to the Threat Index API."
- **From 900px up, two columns.** A 244px sticky **rail** (paper, right border): brand (accent dot, "Threat Index",
  "by Motiontic"); `nav` labelled "Main" in mono-labelled sections: Explore (Home, Index A–Z, Search everything), Browse
  (Vulnerabilities, Exploited in the wild, Breaches, AI incidents, Malicious packages, Techniques, Terms, as `/search`
  filters), Data (Sources, with its count), You (Sign up free, Log in → `/account`); the current link is ink-filled with
  `aria-current="page"`. A sticky **top bar** (`header`, canvas at 90% with blur): a GET search form to `/search`
  (`role="search"`, labelled `q` input up to 680px) and "Log in" / "Sign up free" linking to `/account`. **Main**
  (`main id="content"`): padding 26px 30px 70px, up to 1260px wide. **Footer**: "Data from N public sources, credited
  on every page." (N = `SOURCES.length` from the root loader) linking to `/sources`; `NVD_NOTICE`; "Threat Index by
  Motiontic. Code under Apache-2.0; each source's data keeps its own licence." linking to the repository and
  `DATA_LICENSES.md`; the Explore links again, so phones without JavaScript reach every page.
- **Below 900px**, one column; the rail becomes a 270px drawer behind a menu button (`aria-expanded`, `aria-controls`)
  that Escape, the backdrop or a link closes, returning focus to the button. Below 1100px, home tiles go to three
  columns and the entry side panel drops under the content; below 620px, two. At 390px nothing scrolls sideways (wide
  tables scroll in their own wrapper) and the gutter is 16px.
- **Components** (`app/components/`): skip link, type badge (11px pill tinted per type), chips, result card, compact
  row, panel, tile, table, letter bar (30px mono squares; empty letters are not links), empty state, credit list, gate
  card, SVG CVSS meter. Dates use one UTC formatter (`7 Apr 2025`), never the visitor's locale, so hydration matches.

### 6. Routes

`app/routes.ts` (config-based); `app/root.tsx` holds the document, shell, root loader and error boundary.

- `/`: headline "Every vulnerability, exploit, breach and AI incident, *in one place*." (emphasis in accent-ink), lede,
  large search form, suggestion pills; five count tiles by type (KEV tile in accent-soft); then panels "Exploited in the
  wild, latest" and "Recent breaches" beside "What changed" and "Browse by type".
- `/search`: heading ("Results for “q”", a type name or "Everything") and count; a 220px GET filter form (types,
  "Exploited in the wild", sort, Apply, Clear) that works without JavaScript; result cards whose chips show preview
  facts only ("Exploited in the wild" or "Not on CISA KEV"; "CVSS 9.8").
- `/e/:id`: crumbs; badge, mono ID, alias chips, `h1`, subtitle, chips; a tab strip with Overview current and the
  type's other tabs marked "free account", not links; the summary. Except for `term`, a gate card ("See the full record,
  free", three benefits, Sign up free / Log in → `/account`) over a blurred `aria-hidden` block of static placeholder
  text, never real data. A 300px "At a glance" `aside`: CVSS number and meter (bad colour at 9+) or "Not scored", and
  KEV status with its date (other types: date and subtitle); "Built from N sources". The credit list ends the page.
  Another case or an alias answers `301` to `/e/<key>`; an unknown ID, or one over 100 characters, is a `404`.
- `/index/:letter?`: the letter bar and entries grouped by letter; `/index` shows all; a letter outside `^[a-z0]$` is 404.
- `/sources`: a licence-status filter bar with counts and a table: source, what it gives, way in, cadence, last success
  (sample), status chip (On, On · asked to be safe, Off until written OK, Link-only until OK).
- `/account`: "Accounts aren't open yet. Sign-up with an email code, Google or GitHub comes next. Search and previews
  stay free." No form of any kind.
- The root `ErrorBoundary` renders inside the shell; a 404 links to search (for `/e/:id`, a search for that ID). Stack
  traces show only in `vite dev`. Unmatched paths return HTTP 404, not 200.

### 7. SEO and accessibility

- Each route's `meta`: its own `<title>` ("CVE-2025-3248: Langflow unauthenticated code execution · Threat Index"), a
  description (summaries cut to 160 characters), `og:title`, `og:description`, `og:type`, `og:url`, and a canonical
  link from the request origin. `/search` and `/account` are `noindex`.
- Entry pages add JSON-LD (`WebPage`: `name`, `description`, `identifier`, `datePublished`) through one component that
  escapes `<`, `>`, `&`, U+2028 and U+2029: the app's only `dangerouslySetInnerHTML`.
- `X-Robots-Tag: noindex` plus a meta tag while `SAMPLE_DATA` is true or `TI_ENV` is `staging`. Pages stay fully
  server-rendered, which is what makes entries crawlable once real data arrives. `public/robots.txt` allows all;
  `public/favicon.svg` is the accent dot.
- `<html lang="en">`; landmarks `header`, `nav`, `main`, `aside`, `footer`; one `h1` per page, no skipped levels;
  labelled inputs; `aria-hidden` icons; Biome's accessibility rules on.

### 8. Security headers

`app/lib/security.server.ts` builds them; `app/entry.server.tsx` applies them to every document response (404 and 500
included) and, minus the CSP, to `.data` responses through `handleDataRequest`.

- A fresh 128-bit nonce per request goes to `renderToReadableStream`, `<ServerRouter>`, `<Scripts>` and
  `<ScrollRestoration>` through a React context (`NonceProvider` / `useNonce`), never through loader data.
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<n>'; style-src 'self'; img-src 'self';
  font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
  Only `vite dev` may relax it for hot reload; state exactly what it adds. Sign-in adds Clerk's origins later.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(),
  usb=()`, `Cache-Control: private, no-cache` (each page has its own nonce). `public/_headers`: `nosniff` on static
  files and `public, max-age=31536000, immutable` on `/assets/*`.
- No form collects a password and no form posts: the only forms are GET search forms.

### 9. Checks

- **Typecheck joins `pnpm build`.** The web `typecheck` is `react-router typegen && tsc --noEmit`; typegen only reads
  `routes.ts` and writes `.react-router/types`. Root `typecheck` becomes today's command
  `&& pnpm --filter @ti/web typecheck`. `pnpm build` runs no Vite build and no `workerd`.
- **Lint.** `apps/web/biome.json` (`"root": false`, `"extends": "//"`) ignores `build` and `.react-router`. If Biome
  rejects that, add both paths to the root `biome.json` instead and say so.
- **Node unit tests** in `apps/web/test/`, run by `pnpm test`, cover every rule in sections 3, 4, 7 and 8 that code can
  check: lookups, the preview-only key set, filters, fixtures (`on`/`ask` sources, `EXAMPLE-` IDs), `NVD_NOTICE` once,
  the exact production CSP and fresh nonces, the noindex rule, JSON-LD escaping (a `</script>` title stays inert), the
  date formatter, the style rules (no colour literal outside `tokens.css`, no `style=`, one `dangerouslySetInnerHTML`),
  `wrangler.jsonc` (names, `API` targets, no `${`, the api's `compatibility_date`), and the footer (`renderToString`).
- **Smoke check in `workerd`**: `apps/web/scripts/smoke.mjs` starts `wrangler dev -c <built config> --ip 127.0.0.1
  --port ${PORT:-8710}` with `WRANGLER_SEND_METRICS=false`, always stops it, and exits 1 listing each failure, unless:
  - `/`, `/search`, `/search?q=log4j`, `/search?type=vuln&sig=kev`, `/e/CVE-2025-3248`, `/index`, `/index/l`,
    `/sources`, `/sources?status=on`, `/account` return 200 HTML with their own `<title>`, one `h1`, the `header`,
    `nav`, `main` and `footer` landmarks, the NVD notice, `X-Robots-Tag: noindex`, and a CSP nonce that matches every
    `<script>` in the page;
  - `/e/CVE-2025-3248` has its summary, CVSS 9.8, "Exploited in the wild" and the JSON-LD in the server HTML;
  - `/e/cve-2025-3248` and `/e/GHSA-c995-4fw3-j39m` answer 301 to `/e/CVE-2025-3248`; `/e/CVE-1999-99999`,
    `/no-such-page` and `/index/ab` answer 404 inside the shell; the stylesheet answers 200 with the immutable header;
  - no page has `type="password"`, a `*-password` autocomplete or `method="post"`, and no file under `build/client`
    contains a fixture entry's summary.
- The web `test:workers` script is `react-router build && node scripts/smoke.mjs`; root `test:workers` becomes today's
  command `&& pnpm --filter @ti/web test:workers`, so CI and loop sandboxes run both with `ci.yml` unchanged. No line in
  `vitest.workers.config.mts`: the app uses no binding yet, and the smoke check tests the real build in `workerd`.

### 10. Deploy wiring

- `apps/web/scripts/deploy-web.mjs` exports `buildWeb(target)` (runs `react-router build`, with `CLOUDFLARE_ENV=staging`
  for staging and the variable deleted from the child's environment for production); `builtWebConfig(target)` (follows
  the redirect and throws unless the built `name` is `ti-web-staging` / `ti-web` and `API` targets `ti-api-staging` /
  `ti-api`, so a stale build can't reach the wrong environment; returns the path); `checkWeb(url)` (retries like
  `checkHealth` until `GET /` is 200 HTML). Test `builtWebConfig` with a good config, a wrong name, a wrong binding and
  no redirect file.
- `scripts/deploy.mjs`: `DEPLOY_ORDER` ends with `'web'`, after `api`, because a service binding's target must exist.
  `writeDeployConfig` skips `web`. For `web`: `buildWeb`, `wrangler deploy -c <builtWebConfig(target)>` with no `--env`,
  then `checkWeb` on the printed `workers.dev` URL, falling back to `TI_APP_URL_STAGING` / `TI_APP_URL`.
- `.github/workflows/deploy.yml` doesn't change: `TI_APP_URL` is already passed to the production deploy.
  `scripts/wrangler-config.mjs` (another feature edits it at the same time) and `scripts/preview.mjs` don't change.
- Rewrite `apps/web/README.md` (layout, scripts, the data-module swap point, build-time environments; laptops run
  `pnpm build` only). The PR explains the React Router 8 choice and lists the contrast ratios.

## Not in scope

- Calling `ti-api`. Clerk: sign-in and sign-up routes, the sign-up modal, return to intent, the user menu.
- Watch, save search, export and copy buttons, quick search, a theme toggle (dark follows the system), tabs other than
  Overview, EPSS and exploit details, `/ops`, `sitemap.xml`, HTML caching, Playwright tests, a custom domain.
- Any change in `apps/api`, `apps/collector`, `apps/loader`, `apps/notify`, `packages/`, `e2b/`, `docs/`,
  `vitest.workers.config.mts`, `pnpm-workspace.yaml`, `ci.yml`, `REVIEW.md` or `loops.json`.

## Acceptance criteria

1. `pnpm build` passes with the web typecheck and unit tests in it and starts no `workerd` process; say how you checked.
   Record its wall time on `main` and on this branch.
2. `pnpm test:workers` passes and ends with the web build and every smoke check from section 9.
3. `pnpm --filter @ti/web build` and `CLOUDFLARE_ENV=staging pnpm --filter @ti/web build` pass; the proof shows each
   built config's `name` and `API` target (`ti-web` / `ti-api`, `ti-web-staging` / `ti-api-staging`).
4. A `wrangler dev` run of the built app on port 8710, with `curl -si` of every section 9 route showing the status line,
   the CSP and `X-Robots-Tag` headers, the `<title>` and the `<h1>`, plus the two 301s and three 404s.
5. `rg -n 'type="password"|-password"|method="post"' apps/web` and `rg -n 'fetch\(|env\.API' apps/web/app` find
   nothing. No colour literal is outside `tokens.css`, and every ratio in the PR is ≥ 4.5:1 (3:1 for focus, large text).
6. Screenshots with `/browse` at 1440×900 and 390×844 of `/`, `/search?q=log4j`, `/e/CVE-2025-3248`, `/index`,
   `/sources`, `/account` and a 404, plus `/` and the entry in dark mode if `/browse` can emulate it. At 390px nothing
   scrolls sideways and the drawer opens and closes. Tabbing reaches the skip link first; every focus ring is visible.
7. `apps/web/package.json` has the exact versions in section 1; no other `package.json` gains a dependency; root
   `vitest` is still `^5.1.0`; `pnpm-lock.yaml` holds one `vite` version.
8. `git diff --stat main` lists only `apps/web/**`, root `package.json`, `pnpm-lock.yaml` and `scripts/deploy.mjs`
   (plus root `biome.json` only if section 9 needed it).
9. Proof saved: output for criteria 1–5, `node --version`, the screenshots and the `scripts/deploy.mjs` diff. Deploys
   can't run in the sandbox; the `builtWebConfig` tests stand in for them.

## Changes from the first build of this branch

This branch already implements the spec above, and its code review converged. Two things are left; fix them on
top of the existing commits and don't redo work that already matches the spec.

1. The `301` redirects from `/e/:id` (an alias or a different-case ID) never reach `handleRequest`, so they go
   out without the security headers and without `X-Robots-Tag: noindex`. Every document response, redirects
   included, carries the same headers. Add a test that a redirect has them.
2. QA did not run: the browser skill wasn't allowed in the loop session. It is now. Run the full QA this spec
   asks for: every route at desktop and 390 px width, light and dark, the navigation drawer, keyboard focus
   states, and the sample-data band, with screenshots saved as proof.

`PROOF.md` must describe the whole branch, not only these fixes, because it becomes the PR body. Re-run every
check in the acceptance criteria.
