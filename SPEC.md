# world-pages: public breach, incident and technique pages, and the API routes behind them

## Why

`ti_world` is filling up: the breach parsers and the linker write `breach_notices`, `companies` and
`breach_events`; the AI and cyber-operations parsers write `incidents`; the ATT&CK, ATLAS, CWE and CAPEC parsers
write `techniques`. None of it is visible. The site's rail links "Breaches", "AI incidents", "Techniques" and
"Terms" to `/search?type=…`, which answers "not in the index yet". This change adds public, cached list and detail
routes to `ti-api` for the three kinds, server-rendered pages for each in `ti-web`, and wires the rail and the
search page's type filters to them (plan §8, §9; milestones M5 and M6).

Two rules carry over from the rest of the API and are the point of most tests here:

- **Breach counts are never summed.** A count belongs to its unit (`state_residents`, `individuals`, `accounts`,
  `not_stated`, `claim`) and its jurisdiction. Pages show each one on its own line; no response has a total.
- **Licence display.** `link` sources show only id, title, date and link. `wait` sources are never shown, not even
  inside an aggregate (a count, a jurisdiction list, a company's notice count).

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `ti_world` schema (`packages/db/migrations/world/0001_init.sql`, `0002_notice_name_key.sql`) | `techniques(id, framework, name, parent, summary)`; `vuln_techniques(vuln_key, technique_id, origin)` PK `(vuln_key, technique_id)`; `companies(key, name, cik, domain, ticker, sector, aliases)`; `breach_notices(source, notice_id, company_key, raw_name, occurred_from, occurred_to, discovered, notified, count, count_unit, jurisdiction, data_types, url, event_key, modified, name_key)` indexed by `company_key` and `name_key`; `breach_events(key, company_key, first_seen, dates, counts_by_unit, notice_count, confidence, modified)`; `incidents(source, incident_id, kind ∈ ai/cyber_op/cyber_event, title, date, entities, techniques, url, gated, modified)` |
| Linker (`packages/linker/src/breach.ts`, `company.ts`) | Company keys `cik:<10 digits>`, `domain:<host>`, `name:<slug>:<juris>`. Event keys are `<companyKey>@<from date>` (or `@<source>:<noticeId>`, cut to 189 chars, `-2`… suffixes). `eventRow` stores `counts_by_unit` as `{unit: {jurisdiction or '-': max count}}` over **all** notices, including any from a source that is now hidden. `dates` is `{"from","to"}` JSON or null. Notices without a company have no event |
| `incidents.gated` | Written as 0 and preserved by the linker; nothing sets 1 yet. Treat 1 as "do not show" |
| `vuln_techniques` | Table exists; no parser writes rows yet. Lookups by `technique_id` are not indexed |
| API (`apps/api`) | Public routes use `cachedPublic(c, ttl, path, build)` and `guarded(c, route, fn)` from `lib/cache.ts`; licence via `displayFor(SETTINGS, ids)` in `lib/preview.ts` and `creditsFor(ids, display)` in `lib/credits.ts`. `ReadEnv` has no `DB_WORLD` field, though `wrangler.jsonc` binds `DB_WORLD` (`ti_world`) in every env and the Workers test harness applies the world migrations |
| Source licences | e.g. `hibp`, `sec-edgar`, `hhs-ocr`, `uk-ico`, `avid`, `mitre-attack`, `mitre-atlas`, `cwe`, `capec` on; `ca-ag`, `wa-ag`, `state-ags`, `vcdb`, `aiaaic`, `cfr-tracker`, `umd-cissm`, `csis` ask; `databreaches-net` link; `aiid`, `eurepoc`, `ransomware-live` wait |
| Web (`apps/web`) | Routes in `app/routes.ts`; `app/data/api.server.ts` is the only `fetch` (no visitor headers, 5 s timeout, 2 MiB cap, guards); `app/data/fixture-api.server.ts` serves fixtures mode; shell rail "Browse" links go to `/search?type=…`; `lib/search-params.ts` has `API_TYPES = ['vuln','mal']`, and `routes/search.tsx` shows "not in the index yet" for the other four types. Security headers come from `lib/security.server.ts` through `entry.server.tsx` and `workers/app.ts`. Clerk sign-in and `/account` (accounts-web) are merged; this change does not touch auth |

## What to build

This branch edits: new `apps/api/src/routes/{breaches,incidents,techniques}.ts`, new `apps/api/src/lib/world*.ts`,
three mount lines in `apps/api/src/index.ts`, new `packages/core/src/world-api.ts`, new
`apps/web/app/routes/{breaches,breach,incidents,incident,techniques,technique}.tsx`, and in the web app
`app/routes.ts` (six lines), `components/shell.tsx` (the Browse links), `routes/search.tsx`,
`lib/search-params.ts`, `data/api.server.ts`, `data/types.ts`, `data/fixture-api.server.ts`, plus new
`data/world-guards.ts`, `data/fixtures/world.json`, tests and smoke paths. No migration changes.

### 1. Response types: `packages/core/src/world-api.ts`

```ts
export type CountUnit = 'state_residents' | 'individuals' | 'accounts' | 'not_stated' | 'claim';
export interface BreachCount { unit: CountUnit; jurisdiction: string | null; count: number }
export interface BreachNotice {
  source: string; noticeId: string; name: string; display: 'full' | 'link';
  notified?: string; url?: string;                       // link and full
  occurredFrom?: string; occurredTo?: string; discovered?: string;   // full only
  count?: number; countUnit?: CountUnit; jurisdiction?: string; dataTypes?: string[];
}
export interface BreachSummary {
  key: string; company: { key: string; name: string } | null; firstSeen: string;
  dates?: { from: string; to: string }; noticeCount: number;   // visible notices only
  counts: BreachCount[]; jurisdictions: string[]; sources: string[];
}
export interface BreachDetail extends BreachSummary { notices: BreachNotice[]; credits: Credit[] }
export type IncidentKind = 'ai' | 'cyber_op' | 'cyber_event';
export interface IncidentSummary {
  source: string; incidentId: string; kind: IncidentKind; title: string;
  date?: string; url?: string; display: 'full' | 'link';
}
export interface IncidentDetail extends IncidentSummary {
  entities: string[]; techniques: { id: string; name?: string }[]; credits: Credit[];   // both [] when link
}
export type Framework = 'attack' | 'atlas' | 'cwe' | 'capec';
export interface TechniqueSummary { id: string; framework: Framework; name: string; parent?: string }
export interface TechniqueDetail extends TechniqueSummary {
  summary?: string; parentRef?: { id: string; name: string }; children: TechniqueSummary[];
  vulns: { key: string; title: string; cvss?: number; exploited: boolean }[]; vulnsMore: boolean;
  credits: Credit[];
}
export interface WorldList<T> { items: T[]; page: number; next: number | null; credits: Credit[] }
```

`CountUnit` re-exports the one in `@ti/core/types` if the types line up; do not define it twice. No type in this
file has a field named `total` or any sum of counts.

### 2. Shared rules: `apps/api/src/lib/world.ts`

- `WorldEnv = ReadEnv & { DB_WORLD: D1Database }`.
- `parseListQuery(url, extra)`: `q` trimmed, 1–100 chars, no control characters, lower-cased (else 400
  `bad_query`; absent is fine); `page` integer 1–40, default 1 (else 400 `bad_page`). Page size is fixed at 25;
  a route reads 26 rows to set `next`. Unknown query parameters are ignored.
- `likePattern(q)`: `%…%` with `\`, `%` and `_` escaped, used with `ESCAPE '\'`.
- `visibleSources(env)`: `displayFor` over every registry id → `{ full: string[]; link: string[] }`. Hidden
  sources (licence `wait`, or a KV override to `hidden`) are in neither list, and SQL binds only these lists, so a
  hidden row is never read into a response. Unknown source ids are hidden.
- `cacheKey(path, parts)`: the route builds the cache path from validated values in a fixed order, e.g.
  `/v1/breaches?page=2&q=acme`. TTL 300 s for lists and details, through `cachedPublic` and `guarded` as today.
- Errors are JSON `{ error }`: 400 as above or `bad_id` / `bad_kind` / `bad_framework`, 404 `not_found`,
  500 `internal` (from `guarded`).

### 3. Breaches: `routes/breaches.ts` and `lib/world-breach.ts`

- `GET /v1/breaches?q=&page=` → `WorldList<BreachSummary>`, newest `first_seen` first, then `key` descending.
  An event is listed only when it has at least one visible notice (an `EXISTS` on `breach_notices` by
  `company_key` and `event_key` with `source IN (visible)`, so the `company_key` index is used). `q` matches
  `companies.name` or `breach_notices.raw_name` of a visible notice.
- `GET /v1/breaches/:key` → `BreachDetail`. `key` is URL-decoded, 1–200 printable ASCII characters (else 400
  `bad_id`); 404 when the event is missing or has no visible notice.
- Counts, jurisdictions, `noticeCount` and `sources` are **recomputed at read time** from the visible notices, not
  read from `breach_events.counts_by_unit` or `notice_count` (those include hidden sources).
  `breachCounts(rows)`: only `full` notices with a numeric count; group by (unit, jurisdiction); keep the largest
  count per group; sort by unit then jurisdiction. Never add counts. `jurisdictions` likewise comes from `full`
  notices only.
- `toNotice(row, mode)`: `link` → `source`, `noticeId`, `name` (raw name), `notified`, `url`, `display: 'link'`;
  `full` adds the dates, count, unit, jurisdiction and `dataTypes` (parsed JSON string array, else `[]`). URLs pass
  only when `http:`/`https:`. Notices sort by `notified` then source.
- `dates` comes from the event row when present. `company` from `companies` (null when the event has none).
  `credits` = `creditsFor(sources of visible notices)`. A list page builds its summaries from one notices query for
  all companies on the page (`company_key IN (…)`, filtered to the page's event keys in code).

### 4. Incidents: `routes/incidents.ts`

- `GET /v1/incidents?q=&page=&kind=` → `WorldList<IncidentSummary>`. `kind` may repeat; each must be `ai`,
  `cyber_op` or `cyber_event` (else 400 `bad_kind`); the shorthand `kind=cyber` means `cyber_op` + `cyber_event`.
  Order: `date` descending with nulls last, then `source`, `incident_id`. Always `gated = 0` and visible sources.
  `q` matches `title`.
- `GET /v1/incidents/:source/:id` → `IncidentDetail`. `source` must be a registry id, `id` 1–200 printable ASCII
  (else 400 `bad_id`); 404 when missing, gated or hidden. `full`: `entities` from the JSON list, `techniques`
  resolved to names from `techniques` (unknown ids keep only `id`). `link`: id, title, date, url, kind; empty lists.

### 5. Techniques: `routes/techniques.ts`

- `GET /v1/techniques?q=&page=&framework=` → `WorldList<TechniqueSummary>`; `framework` may repeat (else 400
  `bad_framework`). Order: `framework`, then `id`. `q` matches `id` or `name`. All four frameworks come from `on`
  sources today, but credits still go through `creditsFor` (`attack` → `mitre-attack`, `atlas` → `mitre-atlas`,
  `cwe` → `cwe`, `capec` → `capec`) and a framework whose source is hidden is excluded.
- `GET /v1/techniques/:id` → `TechniqueDetail`. `id` must match
  `^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?|CWE-\d{1,6}|CAPEC-\d{1,6})$` (else 400 `bad_id`). `parentRef` from the
  parent row, `children` = rows whose `parent` is this id (at most 200, ordered by id). `vulns`: up to 50
  `vuln_techniques` rows for this id, joined in code to `DB_VULNS.vulns` preview fields (`key`, `title`, `cvss`,
  `exploited` = `kev_added` not null); `vulnsMore` when there were 51. Empty when the table has no rows.

### 6. Mounting

`apps/api/src/index.ts`: import the three modules and add them to the route list (3 lines). They sit under
`/v1/*`, so a signed-in caller skips the shared cache as on every other public route.

### 7. Web pages

- `app/routes.ts`: `breaches`, `breach/:key`, `incidents`, `incident/:source/:id`, `techniques`,
  `technique/:id`, before the `*` route.
- `api.server.ts` stays the only `fetch` and sends no visitor header. Add to `SiteData`: `breaches(query)`,
  `breach(key)`, `incidents(query)`, `incident(source, id)`, `techniques(query)`, `technique(id)`; the query
  string is built from validated values in a fixed order and path segments with `encodeURIComponent`. 404 →
  `null`; 400 → `ApiBadRequest`; else `ApiUnavailable`. New guards in `data/world-guards.ts` copy known fields,
  drop non-`http(s)` URLs, cap lists (items ≤ 25, notices ≤ 200, children ≤ 200, vulns ≤ 50) and reject a body
  carrying a `total`.
- Fixtures mode: `data/fixtures/world.json` holds invented samples (marked "Invented sample" like `entries.json`):
  two breach events (one with two notices in different units and jurisdictions, one with a `link` notice), three
  incidents (ai, cyber_op, and one `link`), and a technique with a parent, two children and one linked vuln that
  exists in `entries.json`. `fixture-api.server.ts` answers the six routes from it with the same status codes.
- Pages use the existing shell, `Panel`, `Table`, `Chip`, `EmptyState`, `CreditList` and tokens; no new CSS file
  unless a class is missing, then add it to the existing stylesheet. Lists: a GET search box (`q`), filter chips
  (incident kind; technique framework), rows linking to the detail page, a pager with "Next page"/"First page".
  Detail pages:
  - **Breach:** company name, dates, an at-a-glance panel with one line per count ("500 state residents · CA",
    "1,200 individuals", "Count not stated", "Claimed by attacker: 3,000,000"), jurisdictions, then a notices
    table. A `link` notice row shows name, date and "Read at source" only, with a "Link only" chip. The words
    "total" and "in all" never appear.
  - **Incident:** title, kind chip, date, entities, techniques linking to `/technique/:id`, source link.
  - **Technique:** id, framework, name, summary, parent link, children, linked vulnerabilities linking to `/e/:id`
    ("No linked vulnerabilities yet" when empty).
  - Every page ends with its credits.
- SEO via `buildMeta`: detail pages are indexable with a canonical URL and a description built from the data
  (e.g. "Breach notices for Example Co.: 2 notices, first reported 2024-03-04."); list pages are indexable only on
  page 1 with no `q` or filter, else `noindex`. Missing → the not-found page with status 404; API down → the same
  502 page `/e/:id` uses. No JSON-LD in this change.
- Rail (`components/shell.tsx`, Browse): Breaches → `/breaches`, AI incidents → `/incidents?kind=ai`,
  Techniques → `/techniques?framework=attack&framework=atlas&framework=capec`, Terms →
  `/techniques?framework=cwe`, plus "Cyber operations" → `/incidents?kind=cyber`. `current` matches the new paths.
- Search page: `API_TYPES` becomes all six. For each selected world type (`breach`, `ai`, `tech`, `term`) the
  loader calls the matching list endpoint with `q` (page 1) and renders a section of up to 10 rows with a "More
  breaches" link to the list page; `vuln`/`mal` keep using `/v1/search`. With no type selected, behaviour is
  today's (vulnerabilities only). The "not in the index yet" state is removed.

### 8. Tests

- `apps/api/test/world.workers.test.ts`: seeds the local D1 from `apps/api/test/fixtures/world-seed.sql`
  (invented rows, including a `wait`-source notice in the same event as a visible one, a `link` notice, a
  `gated = 1` incident, an `aiid` incident, a technique tree and two `vuln_techniques` rows with matching `vulns`
  rows). Mount the routes on a test app as `public-api.workers.test.ts` does. Cover: each list and detail, paging
  and `next`, `q` with `%` and `_` treated literally, each 400 and 404; counts per unit and jurisdiction with no
  sum and no hidden-source count or jurisdiction; `link` notices and incidents carry only the link fields; hidden
  and gated rows never appear in lists, details or credits; a KV override to `hidden` takes effect; the second
  anonymous request is a cache hit and a signed-in one is `private, no-store`.
- `apps/web/test/world.test.ts` with `fakeApi`: request paths and encoding, no `Authorization` or `Cookie`,
  guard behaviour (bad URL dropped, `total` rejected, caps), rendering of the breach page (separate count lines, no
  "total", link-only row), search with `type=breach` calling `/v1/breaches?q=…`, meta (`noindex` rules,
  canonical). Smoke (`scripts/smoke.mjs`, fixtures mode): add the six pages with their titles and a missing
  breach (404); the existing header checks then run on them.

## Not in scope

- An index on `vuln_techniques(technique_id)` and on `techniques(parent)` (a later migration; today both
  lookups scan small tables).
- Breach notices without a company (no event), company pages, sitemap entries, JSON-LD, mixing world rows into
  `/v1/search` or the search shards, rate limits and error-page work (launch hardening).

## Acceptance criteria

1. `pnpm build`, `pnpm test` and `pnpm test:workers` pass; output in `proof/world-pages/build.txt`,
   `test.txt`, `workers.txt`.
2. No response type or body has a summed count; a test shows two notices in different units and jurisdictions
   come back as two `counts` entries.
3. A `wait` source's notice changes nothing in any response: not counts, jurisdictions, `noticeCount`, `sources`
   or credits (test).
4. `link` notices and incidents expose only id, title/name, date and link (test, both API and page).
5. Gated incidents and hidden sources never appear in lists or details (test).
6. Anonymous responses are cached for 300 s by a key built from validated values only; signed-in ones are
   `private, no-store` (test).
7. Web public calls carry no visitor header (test); every new page has the existing security headers (smoke).
8. The rail and the search type filters reach the new pages and endpoints; "not in the index yet" is gone.
9. QA: run `ti-web` with `wrangler dev` on port 8713 (`--var DATA_SOURCE:fixtures --var TI_ENV:local`) and save
   screenshots to `proof/world-pages/` of `/breaches`, a breach detail (count lines and a link-only notice),
   `/incidents?kind=ai`, an incident, `/techniques`, a technique with children and a linked vuln, `/search?q=…&
   type=breach`, and a phone-width breach page. Also run `ti-api` with `wrangler dev` on port 8714 with a local D1
   loaded from `world-seed.sql` and save the JSON of one list and one detail per kind with `curl`.
10. The PR lists what is left: the two indexes, notices without a company, sitemap and JSON-LD.

## Decisions on the open questions

- "Terms" means CWE weaknesses. The search type mapping in this spec is accepted.
- `incidents.gated = 1` means hidden.
- The extra web files named in this spec (`app/routes.ts`, the API client, types and fixture API) may be edited.
  This change runs alone in the web app.
