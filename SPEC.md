# public-api: entries with licence display rules, receipts, the A–Z index and source status

## Why

The API's public read routes are stubs or rough drafts. `GET /v1/entries/:id` returns raw `vulns` columns in
snake_case to signed-in users, resolves only some aliases, ignores display modes and KV overrides, and its
credits are not the `Credit` shape the web app builds against. `/v1/index/:letter`, `/v1/sources` and
`/v1/entries/:id/receipts` return 501. This change builds `docs/IMPLEMENTATION_PLAN.md` §8 for those four
routes, returning the types in `@ti/core/api`, with licence gates enforced in the API and the Cache API on
public responses.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/entries.ts` | `resolveKey` → `SELECT * FROM vulns`; visitor gets `previewEntry(row)` (snake_case), signed-in gets the whole row incl. `doc_key`; top-level `credits: {source,text}[]`; `public, max-age=300` header but no Cache API. Receipts: `requireUser` + 501 |
| `routes/index-letter.ts`, `routes/sources.ts` | 501 stubs, public |
| `routes/health.ts` | `GET /v1/health` → `{ ok: true }`, mounted before `clerkMiddleware()` in `index.ts` |
| `lib/resolve-key.ts` | Prefix → source map (GHSA, RHSA, USN, DSA/DLA, JVNDB, EUVD, PYSEC/GO/RUSTSEC/MAL); looks up `advisories (source, source_id)`. Ignores the linker's alias rows (`source = 'alias'`) |
| `lib/credits.ts`, `lib/preview.ts` | `credits(ids)` → `{source,text}[]` plus `NVD_NOTICE` for `nvd`; `PREVIEW_FIELDS` list of snake_case columns |
| `lib/env.ts` | `Bindings` has `DB_CONTROL`, `DB_VULNS`, `DB_ADVISORIES`, `DB_USERS`, `BUCKET`, `LOAD`, secrets. It lacks `DB_SIGNALS` and `SETTINGS`, although both are bound in `wrangler.jsonc` (prod and staging) |
| `@ti/core` | `api.ts` (`Credit`, `EntryPreview`, `EntryFull`, `EntryAdvisory`, `EntrySignal`, `EntryChange`, `EntryResponse`, `IndexLetterResponse`, `SourceStatus`, `SourcesResponse`, `ApiError`); `licence.ts` (`displayMode`, `NVD_NOTICE`); `settings.ts` (`readSourceSettings`); `r2-keys.ts` (`rawReceiptKey`, `indexLetterKey`); `ids.ts` (`normaliseId`); `control.ts` (`RUN_STATUSES`) |
| Data | `vulns(key, kind, title, summary, published, modified, cvss, cvss_version, cvss_source, cwe JSON, kev_added, ransomware, epss, …, sources JSON, doc_key)`; `advisories(source, source_id, vuln_key, status, published, modified, url, licence)` with index on `vuln_key`, no title column; `signals(vuln_key, kind, source, ref, first_seen, evidence_date, url)`; `changes(id, entity_key, kind, old, new, at, source)` indexed on `at` only; `runs(id ULID, source_id, started_at, finished_at, status, …)` indexed on `(source_id, started_at)` |
| Receipts | The collector writes `rawReceiptKey(source, runId, step, date of decodeTime(runId))` = `raw/<source>/<yyyy>/<mm>/<dd>/<runId>-<step>.ndjson.gz`. No table records which run touched which entry |
| Tests | `apps/api/test/api.workers.test.ts` has two `/v1/entries` cases asserting the old shape, and the health-before-Clerk test |

## What to build

Edit only `apps/api/src/routes/{entries,index-letter,sources,health}.ts`, `apps/api/src/lib/{credits,preview,
resolve-key,cache}.ts` (new or existing), a new `apps/api/test/public-api.workers.test.ts`, and the two
`/v1/entries` cases in `apps/api/test/api.workers.test.ts` (move them to the new file; leave every other case
there alone). Don't edit `apps/api/src/index.ts`, `lib/env.ts`, `lib/auth.ts`, migrations, Wrangler configs,
`vitest.workers.mts`, any package, or `pnpm-lock.yaml`. Add no dependency (the API has no `ulid`).

### 1. Bindings these routes read

`lib/env.ts` is not edited here. In `lib/preview.ts` export
`type ReadEnv = Bindings & { DB_SIGNALS: D1Database; SETTINGS: KVNamespace }` with a comment that it folds
into `Bindings` later; the routes cast `c.env as ReadEnv` once. Both bindings already exist in the configs.

### 2. Display rules: `lib/preview.ts`

```ts
export type DisplayMap = ReadonlyMap<string, DisplayMode>;
/** displayMode(registry licence, KV override) for each id; ids not in SOURCE_BY_ID map to 'hidden'. */
export async function displayFor(kv: KVNamespace, ids: readonly string[]): Promise<DisplayMap>;
export function toPreview(row: VulnRow, aliases: string[], exploited: boolean, credits: Credit[]): EntryPreview;
export function toAdvisory(row: AdvisoryRow, mode: DisplayMode): EntryAdvisory | null; // null when hidden
```

- `displayFor` makes one `readSourceSettings` call (bulk KV) for the unique ids. An unknown source id is
  `hidden`: data we cannot attribute to a reviewed source is not shown.
- `hidden` (every `wait` source, and any source a KV override hides): its advisories, signals and changes are
  dropped, it is never credited, and its source IDs are not listed as aliases.
- `link`: an advisory keeps only `source`, `sourceId`, `status`, `published`, `url` and `display: 'link'`.
  There is no title column in `advisories`, so there is no title to show; `modified` and `affected` are
  dropped. Its signals keep their metadata fields (`kind`, `source`, `ref`, `firstSeen`, `url`).
- `full`: every `EntryAdvisory` field the table has. `affected` is not stored in D1 and stays absent (later,
  from `docs/vuln/<key>.json`).
- If `vulns.cvss_source` is hidden, `cvss` and `cvssVersion` are omitted.
- Row mapping is camelCase: `cvss_version` → `cvssVersion`, `kev_added` → `kevAdded`. `summary` null → `''`.
  `cwe` is parsed as a JSON string array; bad JSON or non-strings → `[]`. `sources` likewise. Never return
  `doc_key` or any column not in the type.
- `exploited` is true when `kev_added` is set, `ransomware = 1`, or a visible source has an `exploited_wild`
  signal for the key.

### 3. Credits: `lib/credits.ts`

`credits(sourceIds: readonly string[], display: DisplayMap): Credit[]` replaces today's function (same name,
`Credit` shape from `@ti/core/api`). One credit per unique visible id, in first-seen order:
`{ sourceId, name, text: SourceConfig.credit }`. Hidden and unknown ids are skipped. When `nvd` is used, the
`nvd` credit's text is `NVD_NOTICE` and it appears exactly once. Other callers (the search route is built at
the same time) use this signature.

### 4. Alias resolution: `lib/resolve-key.ts`

`resolveKey(env, raw): Promise<string | null>`; `null` means not found.

1. `id = normaliseId(raw)`. An id longer than 128 characters or with a character outside `[A-Za-z0-9._:-]`
   is rejected before any query: the route returns `400 { error: 'bad_id' }`.
2. `vulns` has `key = id` → `id`.
3. `advisories` row `(source = 'alias', source_id = id)` with a non-null `vuln_key` → that key (the linker's
   alias map; covers any ID it has seen).
4. The existing prefix → source map, `advisories (source, source_id)` → `vuln_key`.
5. Otherwise `null` → `404 { error: 'not_found' }`.

Steps 3–4 may run as one `db.batch`. The resolved key must exist in `vulns`, else 404. Cold flaws that live
only in `lookup/vuln/` are not served yet.

### 5. `GET /v1/entries/:id`

- Visitor (`getAuth(c)?.userId` empty): `{ access: 'preview', entry: EntryPreview }`. Queries: the `vulns`
  row; `advisories WHERE vuln_key = ? LIMIT 200` (for aliases: every `source_id` other than the key, from
  alias rows and visible sources, unique and sorted); one `signals` existence check for `exploited_wild`.
  Credits cover the visible ids in `vulns.sources` plus `cvss_source`.
- Signed in: `{ access: 'full', entry: EntryFull }`, adding:
  - `advisories`: non-alias rows through `toAdvisory`, hidden ones dropped, sorted by source then sourceId;
  - `signals`: `signals WHERE vuln_key = ? LIMIT 200`, one `EntrySignal` per row, never merged across kinds,
    sorted by kind then `firstSeen`; hidden sources dropped;
  - `changes`: `changes WHERE entity_key = ? AND at >= <now − 90 days> ORDER BY at DESC LIMIT 20`, hidden
    sources dropped. The `at` bound keeps the scan on `changes_by_time`; there is no `entity_key` index and
    this change adds no migration. Say so in the PR as follow-up;
  - `cwe`;
  - credits over every visible source used by the row, the advisories, signals and changes.
- `aliases` and `credits` are present in both access levels.

### 6. `GET /v1/entries/:id/receipts` (signed in, `requireUser` stays)

No response type exists in `@ti/core/api`; define and export it in `routes/entries.ts`:

```ts
export interface ReceiptsResponse {
  key: string;
  exact: false; // per-entry run ids are not stored yet
  note: string;
  receipts: { sourceId: string; runId: string; status: string; startedAt: string; finishedAt?: string;
              objects: { key: string; uploaded: string; size: number }[] }[];
  credits: Credit[];
}
```

- Sources: the visible ids used by the entry (as in full), at most 10.
- For each: `runs WHERE source_id = ? AND status IN ('ok','heavy') ORDER BY started_at DESC LIMIT 2`.
- For each run: `BUCKET.list({ prefix: raw/<source>/<yyyy>/<mm>/<dd>/<runId>-, limit: 20 })`, the date
  coming from the ULID time of `runId`. Decode the first 10 Crockford base32 characters with a small local
  function (tested), since `ulid` is not an API dependency. At most 20 list calls per request.
- `uploaded` is R2's upload time, within seconds of the fetch; the exact `fetchedAt` is inside the gzipped
  receipt and is not read. `note` says these are the latest successful runs of each source with data on
  this entry, not proven to contain it. No object bodies are returned.

### 7. `GET /v1/index/:letter`

- `letter` lowercased must match `^[a-z0]$` (`0` = keys starting with a digit), else
  `400 { error: 'bad_letter' }`. `cursor` (optional) is a key, ≤ 128 characters, else 400.
- No cursor: `BUCKET.get(indexLetterKey(letter))`; if present and it parses as an `IndexLetterResponse`,
  return it. Its own `cursor` continues into D1 pages.
- Otherwise, from D1: `SELECT key, title FROM vulns WHERE ((key >= ?lo AND key < ?hi) OR (key >= ?lo2 AND
  key < ?hi2)) [AND key > ?cursor] ORDER BY key LIMIT 501`, where the ranges are the letter's upper- and
  lowercase bands (`'0'`–`':'` for digits). 500 items per page; `cursor` = the last key when a 501st row
  exists.

### 8. `GET /v1/sources`

`SourcesResponse` over all of `SOURCES`, in registry order: `id, name, gives, pattern, cadence, licence`,
`display` from `displayFor`, `credit`, `lastSuccess` (max `finished_at` with status `ok` or `unchanged`) and
`lastRunStatus` (status of the run with the latest `started_at`). Two grouped queries on `runs`, one bulk KV
read. `wait` sources are listed with `display: 'hidden'`; that shows their name and status, not their data.

### 9. Caching: `lib/cache.ts`

```ts
export async function cachedPublic(c: Context<AppEnv>, ttlSeconds: number, path: string,
  build: () => Promise<Response>): Promise<Response>;
```

- Auth is decided before the cache is touched. A signed-in request never reads or writes the cache and gets
  `Cache-Control: private, no-store`.
- Visitor: the cache key is `https://cache.internal<path>` built by the route from normalised parts (the
  resolved key for entries, the lowercased letter plus `cursor` for the index). No headers, cookies or other
  query parameters are part of it, so it cannot vary on auth. Only `200` responses are stored, through
  `c.executionCtx.waitUntil(caches.default.put(...))`. Header `Cache-Control: public, max-age=<ttl>`.
- TTLs: entries 300 s, index 600 s, sources 60 s. Receipts are signed-in only and never cached.
- Note in the PR: the Cache API is a no-op on `*.workers.dev`; it works on the custom domain.
- D1, R2 or KV failures return `500 { error: 'internal' }` with no detail; the log line names the route only.

### 10. Tests: `apps/api/test/public-api.workers.test.ts`

Seed local D1 (all databases from the migrations), local R2 and KV in the test. For signed-in requests, mock
`@hono/clerk-auth` with `vi.mock` so `clerkMiddleware` is a pass-through and `getAuth` returns a user only
when a test header is set. If `vi.mock` does not work under the installed `@cloudflare/vitest-plugin`, mount
the route modules on a test Hono app with a stub middleware instead, and say which in the PR. Use
`createExecutionContext`/`waitOnExecutionContext` from `cloudflare:test` (check the installed plugin's
exports) so cache writes finish before the next request. Use distinct keys per test so the cache never leaks.

1. Preview: a visitor gets exactly the `EntryPreview` keys (camelCase), no `cwe`, `advisories`, `signals`,
   `changes`, `doc_key`; `exploited` true from KEV, true from a visible `exploited_wild` signal, false when
   that signal's source is `wait`.
2. Full: signed-in gets `cwe` parsed, advisories, two signals of different kinds kept apart, changes newest
   first and older than 90 days excluded; bad `cwe` JSON → `[]`.
3. Aliases: `cve-…` lowercase; a GHSA in mixed case via the prefix map; an `EUVD-…` and an unprefixed id via
   alias rows; unknown → `404 { error: 'not_found' }`; a 200-character id and one with `/` → 400.
4. Licence: a `zdi` (`link`) advisory has only the link fields; a `vulncheck` (`wait`) advisory and signal
   are absent, not credited and not in `aliases`; KV `source:red-hat` = `{"display":"hidden"}` hides Red Hat;
   KV `{"display":"link"}` on an `on` source makes it link-only; a malformed KV value is ignored; a hidden
   `cvss_source` drops `cvss`.
5. Credits: `Credit` shape; `nvd` in `sources` or as `cvss_source` → exactly one credit with `NVD_NOTICE`;
   an unknown source id is not credited.
6. Cache: visitor → `public, max-age=300`; update the row, request again as a visitor → old title (cache
   hit); signed-in → new title and `private, no-store`; a visitor after that still gets the preview; 404 is
   not cached.
7. Index: R2 page served when present; absent → D1 page in key order, both letter cases, `0` for digits,
   cursor continues with no repeat or gap; `bad_letter` for `ab` and `%`.
8. Sources: 55 entries in registry order; KV override reflected in `display`; `wait` → `hidden`;
   `lastSuccess` and `lastRunStatus` from seeded runs; a source with no runs has neither.
9. Receipts: visitor 401; signed-in with seeded runs and R2 objects at the collector's keys → those keys,
   `exact: false`; a `failed` run is not listed; the ULID decoder matches a known ULID time.
10. Health: `/v1/health` still answers 200 with Clerk misconfigured (the existing test, unchanged).

## Not in scope

Cold flaws from `lookup/vuln/` shards; `affected` ranges and advisory titles (not in D1); an `entity_key`
index on `changes` (needs a migration); per-entry receipt tracking; rate limiting; writing
`lookup/index/*.json` (a nightly job does that later); search; the web pages; any change to `index.ts`,
`lib/env.ts` or `lib/auth.ts`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass; the tests in §10 exist and pass.
2. All four routes return the `@ti/core/api` types (and `ReceiptsResponse`); `tsc` checks the handlers
   against them.
3. No response from these routes contains a `wait` source's data or a hidden source's credit, and a `link`
   source's advisory has only the link fields (tests 4 and 5).
4. Visitor responses carry `public, max-age=<ttl>` and come from the Cache API on a repeat; signed-in
   responses carry `private, no-store` and never touch the cache (test 6). The cache key has no auth input.
5. `/v1/health` returns 200 with Clerk misconfigured.
6. `git diff --stat main` shows only the files listed under What to build.
7. Proof saved: `pnpm build` and `pnpm test:workers` output; `wrangler dev` of the api on port 8700 with
   local D1 seeded through `wrangler d1 execute --local`, and `curl -i` for health, a preview entry by CVE and
   by alias, an unknown id (404), `/v1/index/c`, and `/v1/sources`. Signed-in responses are proven by tests
   only; the sandbox has no Clerk keys, and the PR says so.

## Coordination with work built at the same time

- Keep the existing `credits()` export and its signature working, because the search route is built against it
  at the same time. Add the new shape as a separate export, `creditsFor(ids, display): Credit[]`, and use that
  here.
- Add `GET /v1/sitemap.xml` (public): stream `sitemapKey()` from R2 with `content-type: application/xml` and a
  600 s cache, or `404` when it doesn't exist yet. The web app proxies it.
- In `apps/api/test/api.workers.test.ts`, change only the `/v1/entries` cases. Leave the `/v1/search`
  assertion alone; the search work owns it. Put new tests in new files.
