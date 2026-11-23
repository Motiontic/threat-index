# parsers-sightings: Project Zero, ENISA EUVD and GCVE exploitation parsers and pull config

## Why

"Exploited in the wild" comes from one source today, CISA KEV. Three more public sources record exploitation
from different angles: Google Project Zero's "0day In the Wild" sheet (zero-days caught in real attacks),
ENISA's EU Vulnerability Database (EUVD, with its own exploited flag and an EUVD ID for every flaw), and the
GCVE Vulnerability-Lookup instance (exploitation sightings). Their source files exist but have no `parser`
or `pull`, so every run ends `skipped`. This change adds three parsers and fills `parser` and `pull` in
`project-zero.ts`, `enisa.ts` and `gcve.ts`, using only the patterns that exist on `main`. Shadowserver gets
no pull: it has no public feed (section 6).

## Current state (checked on main, endpoints checked 24 Nov 2026)

| Area | Today |
| ---- | ----- |
| Source files | `project-zero.ts` (fingerprint, weekly), `shadowserver.ts` (since, daily), `enisa.ts` (since, 3h), `gcve.ts` (since, daily). All licence `ask`, which `canIngest` allows, so a wired source runs on staging. None has `parser` or `pull` |
| `packages/parsers/src/` | `kev.ts` (the model for signals), `osv.ts` (advisory + vuln-when-no-CVE), `cve-json5.ts`, `nvd.ts`. `csv.ts` is a stub this change must not touch |
| `fingerprint` pattern | One URL; `format: 'json'` with `itemsPath` + `key`, or `format: 'csv'` with `key` = a header name. Hashes each entry; returns only new or changed ones, ≤ 40 per step. A JSON item body is the whole document cut to one entry (`{ items: [entry], total }`); a CSV item body is one row as `{ <header>: <cell> }`. A row whose key cell is empty is dropped. Follows redirects; 5 MB body limit |
| `since` pattern | Sends `toISOString()` timestamps and a numeric offset. EUVD rejects both (below), so `since` cannot serve EUVD yet |
| Linker | `exploited_wild` from a source other than `cisa-kev` sets no `vulns` column; it is stored as its own `signals` row, key `(vuln_key, kind, source, ref)`. `kind: 'euvd'` is a valid `VulnKind`. `apps/api` resolves `EUVD-` IDs through `advisories` rows with `source = 'enisa'` |
| Test helpers | `fixture()` from `test/fixtures.ts`; `makeCtx`, `route`, `reply` from `packages/patterns/test/helpers.ts` (`osv-sources.test.ts` shows the use) |

Facts checked with curl on 24 Nov 2026 (re-check in the sandbox, section 7):

- **Project Zero.** Sheet `1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY`, tab "All" (`gid=1190662839`). CSV export
  `https://docs.google.com/spreadsheets/d/<id>/export?format=csv&gid=1190662839` answers `307` to
  `*.googleusercontent.com`, then `200 text/csv`, about 260 KB, no ETag or Last-Modified (HEAD works). Header:
  `CVE,Vendor,Product,Type,Description,Date Discovered,Date Patched,Advisory,Analysis URL,Root Cause Analysis,Reported By`.
  414 rows with a CVE cell, newest first, about 11,700 empty rows. Unknown values are `???` (sometimes
  `??? `); one row's CVE cell is `-`; 2 rows have an empty `Date Patched`. Dates are `YYYY-MM-DD`.
- **EUVD.** API docs `https://euvd.enisa.europa.eu/apidoc`. `GET https://euvdservices.enisa.europa.eu/api/search`
  returns `{ items: [...], total }`; `page` is a 0-based page index, `size` ≤ 100 (larger is cut to 100);
  `fromDate`/`toDate` and `fromUpdatedDate`/`toUpdatedDate` accept only `yyyy-MM-dd` (an ISO timestamp gives
  `400`); `exploited=true` filters to exploited entries (1,809 today); results are newest-updated first;
  unknown parameters are ignored; responses are `no-store`, no validator. Entry fields: `id` (`EUVD-YYYY-N`),
  `enisaUuid`, `description`, `datePublished`, `dateUpdated`, `baseScore`, `baseScoreVersion` (`"3.1"`, `"4.0"`),
  `baseScoreVector`, `references` and `aliases` (newline-separated strings, trailing newline), `assigner`,
  `epss`, `exploitedSince` (exploited entries only), `enisaIdProduct`, `enisaIdVendor`; the single-entry
  endpoint `GET /api/enisaid?id=<EUVD id>` adds `enisaIdVulnerability` and `enisaIdAdvisory`. Dates look like
  `Nov 20, 2026, 10:30:42 PM` and are UTC (EUVD-2024-31989 `Apr 12, 2024, 7:20:00 AM` = CVE-2024-3400's
  `2024-04-12T07:20:00.707Z`). Entry page: `https://euvd.enisa.europa.eu/vulnerability/<id>`.
- **GCVE.** `https://db.gcve.eu/api/` runs Vulnerability-Lookup (`/api/swagger.json`).
  `GET /api/sighting/?type=exploited&per_page=100` returns
  `{ metadata: { count, page, per_page }, data: [{ uuid, vulnerability_lookup_origin, creation_timestamp, type, source, content, vulnerability, author: { login } }] }`,
  newest first; `page` is 1-based. `type` is one of `seen`, `published-proof-of-concept`, `exploited`,
  `not-exploited`, `confirmed`, `not-confirmed`, `patched`, `not-patched`.
- **Shadowserver.** Its reports and statistics API (`https://transform.shadowserver.org/api2/`) answers
  `401 Invalid API key or HMAC` without a key and a per-request HMAC signature; no public feed was found.

## What to build

Touch only: new `packages/parsers/src/{project-zero,euvd,gcve-sighting}.ts`, new tests in
`packages/parsers/test/`, new files under `fixtures/{project-zero,enisa,gcve,shadowserver}/`, and the source
files `packages/sources/src/sources/{project-zero,enisa,gcve,shadowserver}.ts`. No dependency, lockfile,
`load.ts`, `csv.ts`, registry, pattern, linker, app or migration change. Never change a `licence` or `credit`.

### 1. Shared rules

- Each module exports a named parser and `export const parse = <named>`, returning `ParseResult<...>` in the
  shapes of `@ti/core/types`. Worker-safe: no `node:` imports, `Buffer`, `process` or `require`. Validate with
  Zod `z.looseObject` like `kev.ts`.
- Input may be an object or its JSON text. A malformed document throws an `Error` whose message starts with
  the parser name (`euvd: …`); never throw for one odd field. A row or entry that carries no usable ID gives
  no records and no error.
- Unknown fields go into `unknownFields` (each at most once), never a crash.
- IDs through `normaliseId`. Store only IDs that match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. Dates as
  `new Date(x).toISOString()`; `firstSeen` and `evidenceDate` as `YYYY-MM-DD`.
- `url` fields only when they parse as `http:` or `https:` URLs.
- Signals stay separate: these parsers emit `exploited_wild` (or `poc`) signals only; nothing sets `kev_added`.

### 2. Project Zero: `packages/parsers/src/project-zero.ts`

```ts
export function parseProjectZeroRow(input: unknown): ParseResult<SignalRecord>;
export const parse = parseProjectZeroRow;
```

- Input: one CSV row object from the fingerprint pattern (`{ CVE, Vendor, …, 'Reported By' }`), or its JSON
  text. Not an object, or no `CVE` key → throw `project-zero: …`.
- The `CVE` cell may in principle hold several IDs: split on commas, whitespace and newlines and keep each
  that `isCve`. None (`-`, empty) → no records.
- Per CVE, one `SignalRecord { vulnKey: <CVE>, kind: 'exploited_wild', source: 'project-zero', ref: <CVE> }`:
  - `firstSeen`: `Date Discovered` if it is a `YYYY-MM-DD` date (after trimming), else `Date Patched` if it is
    one, else no record for that row (the sheet gives no date to stand on);
  - `evidenceDate`: `Date Patched` when it is a date;
  - `url`: `Analysis URL` when it is an http(s) URL, else `Advisory` when it is one.
- Known columns are the eleven in the header above; any other key is an unknown field. `???` is never a value.

### 3. ENISA EUVD: `packages/parsers/src/euvd.ts`

```ts
export function parseEuvdDate(raw: string): string | null; // 'Nov 20, 2026, 10:30:42 PM' or ISO → ISO, else null
export function parseEuvd(input: unknown): ParseResult<VulnRecord | AdvisoryRecord | SignalRecord>;
export const parse = parseEuvd;
```

- Input: a search response `{ items, total }` (any length; the pattern sends one entry), a JSON array of
  entries (the `/api/exploitedvulnerabilities` shape), a single entry (the `/api/enisaid` shape), or JSON text
  of any of these. Anything else throws `euvd: …`.
- `parseEuvdDate`: `^(Jan|…|Dec) (\d{1,2}), (\d{4}), (\d{1,2}):(\d{2}):(\d{2}) (AM|PM)$` read as UTC (12 AM is
  hour 0, 12 PM is hour 12); also accepts an ISO 8601 string; rejects impossible dates.
- Per entry: `id` must match `^EUVD-\d{4}-\d+$`, else skip it. `dateUpdated` must parse, else throw
  `euvd: <id>: missing or invalid dateUpdated`. Aliases: split `aliases` on whitespace, `normaliseId`, drop
  the entry's own ID, keep safe IDs. `cve` = the first alias that `isCve`.
  - Always one `AdvisoryRecord { source: 'enisa', sourceId: <id>, vulnKey: cve ?? null, status: 'active',
    published, modified: <dateUpdated>, url: 'https://euvd.enisa.europa.eu/vulnerability/<id>' }`.
  - With no CVE, also one `VulnRecord { key: <id>, kind: 'euvd', source: 'enisa', title, summary, published,
    modified, cvss, cvssVersion, cvssSource: <assigner>, cwe: [], aliases }`: `title` is the description's
    first sentence (≤ 120 characters), else the ID; `summary` the description, whitespace collapsed, cut to
    300 characters at a word boundary; `cvss` only for a number in 0–10 with `baseScoreVersion` one of `2.0`,
    `3.0`, `3.1`, `4.0`. With a CVE, no vuln record: the CVE's own sources own its text and score.
  - `exploitedSince` that parses → one `SignalRecord { vulnKey: cve ?? <id>, kind: 'exploited_wild',
    source: 'enisa', ref: <id>, firstSeen: <its date>, evidenceDate: <its date>, url: <entry page> }`.
- Known fields: the entry fields listed in Current state; `items` and `total` at the top. `references`,
  `epss`, `baseScoreVector`, `enisaUuid`, `enisaId*` are known but not mapped (EPSS has its own source).

### 4. GCVE sightings: `packages/parsers/src/gcve-sighting.ts`

```ts
export function parseGcveSightings(input: unknown): ParseResult<SignalRecord>;
export const parse = parseGcveSightings;
```

- Input: a sighting list response `{ metadata, data: [...] }` (any length), a single sighting object, or JSON
  text of either. Anything else throws `gcve-sighting: …`.
- Per sighting: `type` `exploited` → `kind: 'exploited_wild'`; `published-proof-of-concept` → `kind: 'poc'`;
  every other type → no record. `vulnerability` must be a safe ID (CVE, GHSA, EUVD, GCVE…), `uuid` a UUID,
  and `creation_timestamp` a date, else skip the sighting.
- Record: `SignalRecord { vulnKey: normaliseId(vulnerability), kind, source: 'gcve', ref: <uuid>, firstSeen:
  <creation date>, url: <source when http(s)> }`. `ref` is the sighting's UUID, so each sighting is one row
  and a re-sent sighting overwrites itself. `content` and `author` are known, not stored.

### 5. Source config

- `project-zero.ts`: `parser: 'project-zero'`, `pull.fingerprint = { url:
  'https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=1190662839',
  format: 'csv', key: 'CVE' }`. A comment says the "All" tab is used and the first run walks about 11 steps.
- `enisa.ts`: change `pattern` from `'since'` to `'fingerprint'`; `parser: 'euvd'`, `pull.fingerprint = { url:
  'https://euvdservices.enisa.europa.eu/api/search?exploited=true&page=0&size=100', format: 'json',
  itemsPath: 'items', key: 'id' }`. This watches the 100 most recently updated exploited entries: every
  3-hour run sends the new or changed ones. A comment explains why `since` is not used yet (date-only
  parameters, page-index paging) and that the full EUVD feed waits for that.
- `gcve.ts`: change `pattern` to `'fingerprint'`; `parser: 'gcve-sighting'`, `pull.fingerprint = { url:
  'https://db.gcve.eu/api/sighting/?type=exploited&per_page=100', format: 'json', itemsPath: 'data',
  key: 'uuid' }`. Daily runs see at most the 100 newest sightings; a comment says backfill and the
  cross-ID correlations are later work.
- `shadowserver.ts`: no `parser`, no `pull`; a comment records the `401` check and that the API needs a key
  and HMAC signing, which `CredentialName` does not cover.

### 6. Fixtures (`fixtures/<source>/`, each folder with a `SOURCE.md`: URL, date, licence, real or hand-written)

Fetch each with curl in the sandbox and trim; hand-write a realistic equivalent only if the fetch fails, and
say so. Licence lines say "no stated licence; source marked `ask`".

- `project-zero/all.csv`: the real header plus about 6 rows: two recent ones, `CVE-2024-53197` (has
  `Date Discovered`), `CVE-2022-26485` (`??? ` discovered), `CVE-2024-7262` (empty `Date Patched`), the `-`
  row, and 3 empty rows. Keep CRLF line ends as served.
- `enisa/exploited-search.json`: the real `exploited=true` response cut to 3 entries; `enisa/entry.json`:
  one real `/api/enisaid` response; `enisa/no-cve.json`: hand-written entry with only a GHSA alias, a 4.0 score
  and one unknown field.
- `gcve/sightings.json`: the real `type=exploited&per_page=3` response, with one hand-added
  `published-proof-of-concept` and one `seen` sighting (marked in `SOURCE.md`).
- `shadowserver/SOURCE.md` only: the `401` check and why there is no pull.

### 7. Tests (`packages/parsers/test/`, Node, fixtures through `fixture()`)

- `sightings.test.ts`:
  - **project-zero:** run the fingerprint pattern's `fetch` (from `packages/patterns/src/fingerprint`) with
    `makeCtx` serving `all.csv` for the export URL; parse each item. Expect one signal per CVE row with the
    right `firstSeen` (discovered for 53197, patched for 26485), `evidenceDate`, `url` (analysis URL, else
    advisory, never `???`), none for `-`; and 7262 uses its discovered date. A row with an extra column
    reports it in `unknownFields`; a non-object throws.
  - **euvd:** `parseEuvdDate` on `12:00:00 AM`, `12:30:00 PM`, `7:20:00 AM`, ISO input, `Feb 30` → null;
    the search fixture gives an advisory with the CVE as `vulnKey` and an `exploited_wild` signal keyed by
    the CVE with `ref` the EUVD ID; `no-cve.json` gives an `euvd` vuln (GHSA alias, score, version) and a
    `null`-`vulnKey` advisory and reports the unknown field; the array and single-entry forms give the same
    records; a missing `dateUpdated` throws; the pattern-cut form (`{ items: [one], total }`) works.
  - **gcve-sighting:** `exploited` → `exploited_wild`, `published-proof-of-concept` → `poc`, `seen` →
    nothing; `ref` is the UUID; an unsafe `vulnerability` is skipped.
- `sources-sightings.test.ts`: each wired source's `parser` loads through `loadParser`; pull blocks and
  patterns equal section 5; `shadowserver` has neither; licence and credit values equal main's; the three
  parser files contain no `node:` import, `Buffer`, `process.` or `require(`.
- `link-sightings.test.ts`: the parsed fixtures through `link()` with `makeFake()` (as
  `link-cve-nvd.test.ts` does): separate `signals` rows per source, `kev_added` still null, an `advisories`
  row `('enisa', <EUVD id>)` with the CVE, and a `vulns` row keyed by the EUVD ID for `no-cve.json`.

## Not in scope

- Shadowserver ingestion (needs an API key, HMAC signing and a licence decision).
- The full EUVD feed (all entries by `fromUpdatedDate`): needs a `since` option for date-only parameters and
  page-index paging, which is a pattern change. Backfilling older exploited EUVD entries and GCVE sightings.
- GCVE cross-ID correlations, GNA publications, KEV catalogues and comments; Project Zero's yearly tabs.
- `DATA_LICENSES.md`, the registry, patterns, linker, collector and API.

## Acceptance criteria

1. `pnpm build` passes (lint, typecheck, Node tests) and `pnpm test:workers` still passes.
2. `loadParser('project-zero')`, `loadParser('euvd')` and `loadParser('gcve-sighting')` return modules whose
   `parse` returns `{ records, unknownFields }`.
3. The tests in section 7 pass using only fixtures; no test reaches the network.
4. `git diff --stat main` lists only the paths allowed in "What to build"; `pnpm-lock.yaml` and every
   `package.json` are unchanged; `rg "licence|credit" packages/sources/src/sources/{project-zero,enisa,gcve,shadowserver}.ts`
   matches main.
5. Each fixture folder has a `SOURCE.md` saying where each file came from, when, and what was trimmed or
   hand-written.
6. Proof saved: `pnpm build` and `pnpm test:workers` output; one curl per wired URL (status, content type,
   size, and for EUVD a `fromDate=<ISO timestamp>` call showing the `400`); the Shadowserver `401`; the
   `link()` rows by table. The PR lists every endpoint check that failed or differed from this spec.

## Decisions on the open questions

- Changing `pattern` on `enisa.ts` and `gcve.ts` to `fingerprint` is accepted.
- Licence `ask` sources ingest by design (`canIngest`) and show with credit, so pulling them on staging is
  intended.
