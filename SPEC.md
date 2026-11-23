# web-public: the public pages read live records from ti-api through the service binding

## Why

`ti-web` renders every public page (plan §9) from hand-written fixtures, behind a "sample data" band and
`X-Robots-Tag: noindex`. The public API routes (`/v1/search`, `/v1/entries/:id`, `/v1/index/:letter`,
`/v1/sources`) are built alongside this change, and their response shapes are fixed in `@ti/core/api`. This change
swaps the web data module to call `ti-api` over the `API` service binding with those types, so pages show real
records, entry previews are crawlable, and the band and `noindex` go away. Fixtures stay, now served by an in-process
fake of the API, for tests and for local runs. Sign-in is not part of this change: locked tabs stay locked.

This branch edits only `apps/web/**`. It adds no dependencies.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/web/app/data/data.server.ts` | `SAMPLE_DATA = true`; `getData(request)` returns sync lookups over `fixtures/entries.json` and `changes.json`: `home`, `search`, `entry`, `index`, `sources` |
| `apps/web/app/data/types.ts` | Its own shapes: `EntryPreview` with `type`, `subtitle`, snake_case `kev_added`; `credits: string[]` |
| Noindex | `shouldNoindex(sampleData, tiEnv)` in `app/lib/security.server.ts`, used by `root.tsx`, `entry.server.tsx` and `workers/app.ts` |
| `wrangler.jsonc` | `API` binding to `ti-api` / `ti-api-staging`; comment says nothing calls it yet. `TI_ENV` var |
| Routes | `/`, `/search` (types, KEV, sort; max 20, no paging), `/e/:id` (301 for case or alias, 404 unknown, JSON-LD, gate card, locked tabs), `/index/:letter?`, `/sources`, `/account` |
| Checks | Node tests in `apps/web/test/`; `scripts/smoke.mjs` runs `wrangler dev` on the built config at port 8710 and expects `X-Robots-Tag: noindex` on every page |
| `@ti/core/api` | `EntryPreview` (camelCase, `kind`, `exploited`, `kevAdded`, `epss`, `credits: Credit[]`), `EntryResponse`, `SearchHit`, `SearchResponse` (`hits`, `total`, `cursor`, `credits`), `IndexLetterResponse`, `SourceStatus`, `SourcesResponse`, `ApiError` |
| `@ti/core/r2-keys` | `sitemapKey()` → `sitemap.xml`. No API route serves it yet |

## What to build

### 1. Data mode

- `wrangler.jsonc`: add `vars.DATA_SOURCE: "api"` at the top level and in `env.staging`; drop the "nothing calls it"
  comment. `app/env.d.ts` adds `DATA_SOURCE?: string`.
- `app/data/mode.server.ts`: `export type DataMode = 'api' | 'fixtures'`;
  `dataMode(env: { DATA_SOURCE?: string; API?: Fetcher }): DataMode` is `'api'` only when `DATA_SOURCE === 'api'`
  and `API` is set, else `'fixtures'`. A misconfigured deploy therefore shows the band and stays out of search engines.
- Local runs without ti-api: `wrangler dev … --var DATA_SOURCE:fixtures`. The README says so.
- `scripts/deploy-web.mjs` `builtWebConfig` also throws unless the built `vars.DATA_SOURCE` is `"api"`; add that case
  to its tests.

### 2. The API client: `app/data/api.server.ts`

- `createSiteData(api: Pick<Fetcher, 'fetch'>, mode: DataMode): SiteData`. Every method is `async`. Loaders call only
  `getData(request)` in `data.server.ts`, which reads `env` from `cloudflare:workers` and passes `env.API` in api mode
  or `{ fetch: fixtureApi }` in fixtures mode. Only `api.server.ts` calls `fetch`.
- Requests: `GET https://ti-api.internal<path>` with `Accept: application/json` and an
  `AbortSignal.timeout(5000)`. The web builds every query string itself from validated values (section 4); it never
  copies the visitor's query string, and it never forwards `Cookie`, `Authorization` or any other visitor header, so
  every answer is a preview and API caching never varies on the visitor.
- Responses: 200 → read the text (over 2 MiB is an error), `JSON.parse`, then a hand-written guard per type in
  `app/data/guards.ts` that checks required fields and **copies only the fields the page uses** into a new object.
  An `EntryResponse` with `access: 'full'` is reduced to the `EntryPreview` fields. 404 → `null`. 400 → an
  `ApiBadRequest` carrying `ApiError.error`. Anything else (5xx, timeout, network error, failed guard) → `ApiUnavailable`.
- Methods and paths (each id or letter goes through `encodeURIComponent`):
  - `entry(id)` → `/v1/entries/:id` → `EntryPreview | null`;
  - `search(params)` → `/v1/search?…` → `SearchResponse`;
  - `index(letter, cursor?)` → `/v1/index/:letter` → `IndexLetterResponse | null`;
  - `sources()` → `/v1/sources` → `SourcesResponse`;
  - `sitemap()` → `/v1/sitemap.xml` → the `Response` when it is 200 with an XML content type, else `null`.
- `app/data/types.ts` re-exports the `@ti/core/api` types and keeps only web-side shapes (`SearchParams`, `SiteData`,
  `EntryType`). Remove `subtitle` and snake_case fields from the pages.
- `displayType(kind?: string, key?: string): EntryType`: `mal` → `mal`; `cve`, `ghsa`, `osv`, `euvd`, `other` → `vuln`;
  `breach`, `ai`, `tech`, `term` pass through (fixtures only); no kind → `MAL-` key prefix gives `mal`, else `vuln`.
  Search hits carry no `kind` in the contract, so the client reads an optional `kind` when present.

### 3. The fixture API: `app/data/fixture-api.server.ts`

`fixtureApi(request: Request): Promise<Response>` answers the four `/v1/*` routes over the existing fixtures in
exactly the `@ti/core/api` shapes, with the same `credits` rule as the API (each cited source's registry credit, the
NVD notice once when `nvd` is cited). It implements `q`, `type`, `sig`, `sev`, `year`, `sort` and an opaque cursor
(20 per page), `/v1/index/:letter` from the existing bucket rule, and `/v1/sources` from `SOURCES` with the existing
sample last-success times. It adds `kind` to hits and entries (`cve` for CVEs, else the fixture type). It never
answers `/v1/sitemap.xml` (404). `changes.json` and the "What changed" panel are removed.

### 4. Pages

All pages keep the shell, components, tokens, CSP nonce and accessibility rules already in place.

- **`/`**: headline, lede, search form and suggestion pills as today. "Browse by type" tiles **without numbers** (no
  count endpoint exists; never show invented totals). One panel, "Exploited in the wild, latest": the first 5 hits of
  `search({ sig: ['kev'], sort: 'new' })`. If that call fails or returns 400, leave the panel out; the page is still 200.
  Remove the count tiles, "Recent breaches" and "What changed".
- **`/search`**: validated params, unknown values dropped: `q` trimmed, ≤ 200 characters; `type` ∈ `vuln`, `breach`,
  `ai`, `mal`, `tech`, `term`; `sig` ∈ `kev`; `sev` ∈ `critical`, `high`, `medium`, `low`; `year` matching
  `^(19|20)\d{2}$`; `sort` ∈ `rel`, `new`; `cursor` matching `^[A-Za-z0-9_-]{1,200}$`. In api mode, a `type` filter
  naming only types the API does not hold (`breach`, `ai`, `tech`, `term`) shows the empty state "<Type plural> are not
  in the index yet" without an API call. No `q` and no filter: no API call, an empty state with browse links. The GET
  filter form gains Severity and Year (a select of the last ten years plus "Any"). Results: the heading, "N results"
  from `total`, hit cards (badge from `displayType`, key, title, summary, chips "Exploited in the wild" or "Not on
  CISA KEV" for vulns, "CVSS 9.8", published date), then a `nav` labelled "Pages" with "Next page" (same params plus
  `cursor`) when the response has one and "First page" when the request had one. API 400 → the empty state "Add a word
  or an ID to search" (200). The search page stays `noindex`.
- **`/e/:id`**: an id over 100 characters or outside `^[A-Za-z0-9._:-]+$` is 404 without an API call. Otherwise
  `entry(id)`: `null` → 404; a different `key` → 301 to `/e/<key>`. Server-rendered: badge, mono key, alias chips,
  `h1` title, chips (exploited, CVSS with `cvssVersion` when present), the locked tab strip exactly as today, the
  summary, the gate card (not for `term`) over the static blurred placeholder, the credit list. "At a glance": CVSS
  number and meter or "Not scored", CISA KEV "Added <date>" or "Not on the list", EPSS as a percentage when present,
  published and modified dates, "Built from N sources" (N = credits). Meta: `<title>` "`<key>: <title> · Threat
  Index`", description = summary cut to 160, canonical `/e/<key>`. JSON-LD `WebPage` adds `dateModified` when present.
- **`/index/:letter?`**: the letter bar with every letter `a`–`z`, `0` as a link (counts are unknown in api mode).
  `/index` shows the bar and a one-line prompt; no API call. `/index/<l>` (`^[a-z0]$`, else 404) lists `items` as
  key + title links, with "Next page" through `?cursor=` (same pattern as search). API 404 or no items → the empty
  state "Nothing under this letter yet" (200, `noindex`).
- **`/sources`**: the licence filter bar with counts computed from the response, and the table: source, what it gives,
  way in (existing `WAY_IN` map over `pattern`), cadence, last success (UTC date and time, or "Never"), last run
  status when present, licence chip. The "(sample)" wording appears only in fixtures mode.
- **Credits** (`CreditList`): `name` then `text`; `name` links to `url` only when it parses as an `https:` URL.
- **Errors**: `ApiUnavailable` → the root error boundary with status **502**, "The index is not answering", a link to
  search. 404 and 502 pages carry `noindex`. Stack traces still show only in `vite dev`.

### 5. Indexing and the band

- `shouldNoindex({ mode, tiEnv, status })` replaces the two-argument form: true when `mode === 'fixtures'`, when
  `tiEnv === 'staging'` (staging must never compete with production in search results), or when `status >= 400`.
  `root.tsx`, `entry.server.tsx` (document status), `handleDataRequest` (response status) and `workers/app.ts` use it;
  the error boundary always renders the robots meta tag. `/search` and `/account` keep their `noindex` meta.
- The sample-data band renders only in fixtures mode. `SAMPLE_DATA` is removed.

### 6. Sitemap

`app/routes/sitemap.ts` is a resource route for `/sitemap.xml`. In api mode it calls `sitemap()` and streams the body
with `Content-Type: application/xml; charset=utf-8`, `Cache-Control: public, max-age=3600` and
`X-Content-Type-Options: nosniff`; anything else, and every request in fixtures mode, is a plain-text 404. No
ti-api route serves `/v1/sitemap.xml` yet, so in production it answers 404 until the API adds that read-only route over
`sitemapKey()`. The web gets no R2 binding. `robots.txt` is unchanged.

### 7. Tests (Node, `apps/web/test/`, run by `pnpm test`)

A `fakeApi(routes)` helper returns a `Fetcher` that records each `Request` and answers from a map of path → status
and body. Cover:

- request building: paths, `encodeURIComponent` of ids and letters, the exact query string for each filter, dropped
  unknown values, `q` and cursor limits, no `Cookie` or `Authorization` sent even when the incoming request has them;
- responses: guards accept the contract shapes and reject missing required fields; `access: 'full'` is reduced to
  preview fields; 404 → `null`; 400 → `ApiBadRequest`; 500, timeout, oversized and invalid JSON → `ApiUnavailable`;
- `dataMode` for each combination; `displayType`; `shouldNoindex` for every mode, env and status;
- `fixtureApi`: each route's shape, filters, cursor paging, credits with the NVD notice once, 404 for sitemap;
- `CreditList` renders a link only for `https:` URLs (`renderToString`);
- the sitemap route: XML passed through with its headers; non-200 and fixtures mode → 404;
- existing tests updated to the new shapes; every rule they check that still applies stays checked. The worker test
  covers a redirect in both modes (noindex only in fixtures mode or staging).

### 8. Smoke checks in `workerd`

- `scripts/stub-api/wrangler.jsonc` (`name` `ti-api`, `main` `./worker.ts`, the web's `compatibility_date`) and
  `worker.ts`, which answers with `fixtureApi`, plus two test hooks: `/v1/entries/CVE-1900-0500` → 500, and
  `/v1/sitemap.xml` → a two-URL sitemap.
- `scripts/smoke.mjs --mode fixtures|api`. Fixtures mode (port 8710) is today's run with
  `--var DATA_SOURCE:fixtures`: every existing check, band and `noindex` included. Api mode (port 8711) runs
  `wrangler dev -c <built config> -c scripts/stub-api/wrangler.jsonc` so the `API` binding reaches the stub, and checks:
  - the same pages and landmarks, titles, one `h1`, NVD notice and CSP nonces as today, plus
    `/search?q=log4j&sev=critical&year=2021` and `/search?type=vuln&sig=kev`;
  - no band and **no** `X-Robots-Tag` on `/`, `/e/CVE-2025-3248`, `/index/c` and `/sources`; `noindex` on `/search`;
  - `/e/CVE-2025-3248` server HTML has the title, summary, CVSS 9.8, "Exploited in the wild", credits and JSON-LD;
  - the two 301s and the three 404s as today, each 404 with `X-Robots-Tag: noindex`;
  - `/e/CVE-1900-0500` → 502 inside the shell with `noindex`;
  - `/sitemap.xml` → 200 XML with `nosniff`;
  - no `type="password"`, `-password` autocomplete or `method="post"`; no fixture summary under `build/client`.
- If two `-c` flags don't bind the stub, run the stub as a second `wrangler dev` (the local dev registry connects
  them) and say so. The web `test:workers` script runs the build, then both modes.

## Not in scope

- Sign-in, sign-up, the gate modal, return to intent, forwarding a session, `/account` changes, `/ops`.
- Any file outside `apps/web/**`: API routes (including `/v1/sitemap.xml`), `@ti/core`, other Wrangler configs, CI.
- An R2 binding for the web, HTML caching, count tiles, "What changed", tabs other than Overview, a theme toggle,
  forwarding the visitor's IP for API rate limits, Playwright tests.

## Acceptance criteria

1. `pnpm build` passes (lint, typecheck, unit tests); then `pnpm test:workers` passes and ends with both smoke modes,
   then `pnpm build` again passes in the same checkout. Save the output.
2. `rg -n 'fetch\(' apps/web/app` finds calls only in `app/data/api.server.ts`; `rg -n 'env\.API' apps/web/app` only
   in `app/data/data.server.ts`; `rg -n 'SAMPLE_DATA|changes.json' apps/web` finds nothing.
3. A unit test proves no visitor `Cookie` or `Authorization` header reaches the binding, and one proves a `full`
   response renders only preview fields.
4. `curl -si` against the api-mode smoke run on port 8711 for `/`, `/search?q=log4j`, `/e/CVE-2025-3248`,
   `/e/cve-2025-3248`, `/e/CVE-1999-99999`, `/e/CVE-1900-0500`, `/index/c`, `/sources` and `/sitemap.xml`, showing the
   status line, `Content-Security-Policy`, `X-Robots-Tag` (or its absence), `<title>` and `<h1>`.
5. Built configs: production and staging both have `DATA_SOURCE` `"api"`, `ti-web` / `ti-api` and
   `ti-web-staging` / `ti-api-staging`; `builtWebConfig` tests include a wrong `DATA_SOURCE`.
6. QA with `/browse` on the api-mode smoke run, at 1440×900 and 390×844: `/`, `/search?q=log4j` (with a filter
   applied and the Pages nav), `/e/CVE-2025-3248`, `/index/c`, `/sources`, a 404 and the 502. At 390px nothing scrolls
   sideways and the drawer opens and closes; tab focus is visible; no band shows. One fixtures-mode screenshot of `/`
   shows the band. Screenshots saved.
7. No colour literal outside `tokens.css`, no `style=` attribute, one `dangerouslySetInnerHTML`; `package.json` and
   `pnpm-lock.yaml` unchanged.
8. `git diff --stat main` lists only `apps/web/**`.
9. `PROOF.md` holds criteria 1–8 and states that ti-api has no `/v1/sitemap.xml` route yet, so production
   `/sitemap.xml` answers 404 until it does.
