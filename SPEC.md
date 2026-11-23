# parsers-ai-events: AVID, AIAAIC and CFR Cyber Operations Tracker parsers and pull config

## Why

The `incidents` table has a linker mapping (`map/incident.ts`) and a home in `ti_world`, but no source feeds it.
Six registry sources describe AI incidents and state cyber operations: MIT AI Risk Repository, AVID, AIAAIC,
CFR Cyber Operations Tracker, CSIS Significant Cyber Incidents and UMD CISSM. Their source files have no
`parser` or `pull`, so every run ends `skipped`. Three of them publish a stable machine-readable feed: AVID (a
GitHub repo of JSON reports), AIAAIC (a public Google Sheet with a CSV export) and CFR (a static CSV). This change
adds a parser for each and fills `parser` and `pull` in their source files, using only patterns on `main`. The
other three have no usable feed today; they get a comment and a `SOURCE.md` saying why (section 6).

## Current state (checked on main, endpoints checked 24 Nov 2026)

| Area | Today |
| ---- | ----- |
| Source files | `avid.ts` (git, weekly, `on`), `aiaaic.ts` (heavy, weekly, `ask`, `heavy: true`), `cfr-tracker.ts` (page, weekly, `ask`), `mit-ai-risk.ts` (heavy, monthly, `on`), `csis.ts` (heavy, monthly, `ask`), `umd-cissm.ts` (heavy, monthly, `ask`). None has `parser` or `pull` |
| `IncidentRecord` (`@ti/core/types`) | `{ source, incidentId, kind: 'ai' \| 'cyber_op' \| 'cyber_event', title, date?, entities?, techniques?, url? }`. No summary, year or company-key field |
| Linker | `incidentRow` stores `date` only when it starts `YYYY-MM-DD` (`isoDate`), `entities`/`techniques` as sorted unique JSON lists, `url` through `httpUrl`; returns null when nothing changed. Key `(source, incident_id)` |
| `git` pattern | Item body is a `GitFile { path, status, text }`; `include` globs (`*` stays in one segment). With no cursor it hands the repo archive to a `first-load` job and settles the cursor at HEAD, so later runs see only new commits |
| `fingerprint` pattern | As used by `project-zero`: one URL, `format: 'csv'`, `key` = a header name; item body is one row `{ <header>: <cell> }`; a row with an empty key cell is dropped; ≤ 5,000 rows, 5 MB, 40 items per step |
| Parsers to copy | `project-zero.ts` (CSV row input, `day()`, `httpUrl()`), `osv.ts` `unwrap()` (GitFile / JSON text / object) |

Facts checked with curl on 24 Nov 2026 (re-check in the sandbox, section 7):

- **AVID.** Repo `avidml/avid-db`, branch `main`, MIT licence. 1,712 files `reports/2026/AVID-2026-R*.json`, plus
  `reports/{2022,2023,2025}/`, 40 `vulnerabilities/{2022,2023}/AVID-*-V*.json`, and `reports/review/` (copies under
  review: exclude). A report has `data_type: "AVID"`, `data_version` (`0.1` to `0.3.3`), `metadata.report_id`
  (a vulnerability has `metadata.vuln_id`), `affects.{developer[], deployer[], artifacts[{type,name}]}`,
  `problemtype.{classof, type, description.value}` (a one-line title), `references[]`, `description.value`
  (long), `impact.avid.{risk_domain, sep_view, lifecycle_view, taxonomy_version}`, from 0.3 also
  `impact.cvss` and `impact.cwe[{cweId}]`, `credit[]`, `reports[]` (vulnerabilities), `metrics[]` (some
  reports), and dates `published_date` / `last_modified_date` (newer) or `reported_date` (older), `YYYY-MM-DD`.
  Report pages `https://avidml.org/database/<lower-case id>/` answer 200; vulnerability pages answer 404.
- **AIAAIC.** Sheet `1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI`, tab "Incidents" (`gid=888071280`). Row 1 is a
  banner and row 2 the header, so the export must start at row 2:
  `https://docs.google.com/spreadsheets/d/<id>/export?format=csv&gid=888071280&range=A2:T` (307 to
  `*.googleusercontent.com`, then `200 text/csv`, about 966 KB, no ETag). Header:
  `AIAAIC ID#,Incident headline,Occurred,Deployer,Developer,System name,Technology,Purpose,News trigger (taxonomy),Ethical issue (taxonomy),Impacted area,,External harm (taxonomy),,,Harm status,Consequence (taxonomy),Response (taxonomy),Summary/links,`.
  The next row is a sub-header with an empty ID cell (the pattern drops it). 2,259 incidents, IDs `AIAAIC\d+`
  (one duplicated), newest first. `Occurred` is a year (`2025`), a range (`2023-2024`, `2024-`) or empty, never
  a full date. Lists are `; `-separated. `Summary/links` is the incident's aiaaic.org page.
- **CFR.** `https://static.cfr.org/cyber-operations/data/cyber-operations-incidents.csv`, `200 text/csv`,
  558 KB, ETag and Last-Modified (13 Nov 2025). Header:
  `Title,Date,Affiliations,Description,Response,Victims,Sponsor,Type,Category,Sources_1,Sources_2,Sources_3`.
  897 rows, no ID column. `Date` is `YYYY-MM-DD` or empty (19 rows). 5 titles repeat; 2 of them repeat with
  the same date and differ in `Affiliations` (e.g. "Targeting of Afghan telecommunication firm Roshan",
  2021-09-28, Calypso / RedFoxTrot). `Affiliations` is free text: `APT 36`, `Iran, APT 35`,
  `Also known as Cold River, Seaborgium, TA446, TAG-53`. `Sponsor` is a country name or empty. `Victims` is a
  sentence. CFR's own incident pages (`/cyber-operations/<slug>/`) use slugs that cannot be derived from the CSV.

## What to build

Touch only: new `packages/parsers/src/{avid,aiaaic,cfr-cyber-ops}.ts`, new tests in `packages/parsers/test/`,
new files under `fixtures/{avid,aiaaic,cfr-tracker,mit-ai-risk,csis,umd-cissm}/`, and the source files
`packages/sources/src/sources/{avid,aiaaic,cfr-tracker,mit-ai-risk,csis,umd-cissm}.ts`. No dependency,
lockfile, `load.ts`, registry, pattern, linker, app or migration change. Never change a `licence` or `credit`.

### 1. Shared rules (each parser keeps its own small helpers; no shared module)

- Each module exports a named parser and `export const parse = <named>`, returning
  `ParseResult<IncidentRecord>`. Worker-safe: no `node:` imports, `Buffer`, `process` or `require`. Validate
  with Zod `z.looseObject` as `project-zero.ts` does.
- Input may be an object or its JSON text. A malformed input throws an `Error` whose message starts with the
  parser name (`avid: …`); never throw for one odd field. A row or file with no usable ID gives no records.
- Unknown fields go into `unknownFields` (each at most once).
- `incidentId` must match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, else no record.
- `title`: trimmed, whitespace collapsed, cut to 200 characters at a word boundary. Empty title → no record.
- `date`: only a real `YYYY-MM-DD` date (checked as `project-zero.ts` `day()` does). Years and ranges are
  not padded into fake dates: the field is left out.
- `entities`: each trimmed and whitespace-collapsed; drop empty, `Unknown`, `N/A`, `None` (any case) and any
  entry over 100 characters; unique in first-seen order; at most 20.
- `techniques`: only IDs of a framework we store (`CWE-\d+`, `T\d{4}(\.\d{3})?`, `AML\.T\d{4}(\.\d{3})?`).
- `url` only when it parses as an `http:` or `https:` URL.
- Metadata only: no description, victim text or summary is copied into any record.

### 2. AVID: `packages/parsers/src/avid.ts`

```ts
export function parseAvid(input: unknown): ParseResult<IncidentRecord>;
export const parse = parseAvid;
```

- Input: a `GitFile` (`{ path, status, text }`), a report or vulnerability object, or JSON text of either. A
  `GitFile` with `status: 'removed'` or `text: null` → no records. Invalid JSON or a non-object → throw `avid: …`.
- ID: `metadata.report_id ?? metadata.vuln_id`, must match `^AVID-\d{4}-[RV]\d{3,5}$`, else no records.
- Record `{ source: 'avid', incidentId: <id>, kind: 'ai', title, date, entities, techniques, url }`:
  - `title`: `problemtype.description.value`, else the ID;
  - `date`: `published_date`, else `reported_date`;
  - `entities`: `affects.developer`, then `affects.deployer`, then each `affects.artifacts[].name`;
  - `techniques`: `impact.cwe[].cweId` that match `CWE-\d+`. AVID's own SEP and lifecycle codes are not stored;
  - `url`: an `R` ID → `https://avidml.org/database/<id lower-cased>/`; a `V` ID →
    `https://github.com/avidml/avid-db/blob/main/vulnerabilities/<year>/<id>.json`.
- Known top-level fields: `data_type`, `data_version`, `metadata`, `affects`, `problemtype`, `metrics`,
  `references`, `description`, `reports`, `impact`, `credit`, `published_date`, `last_modified_date`,
  `reported_date`. Nested fields are not reported.

### 3. AIAAIC: `packages/parsers/src/aiaaic.ts`

```ts
export function parseAiaaicRow(input: unknown): ParseResult<IncidentRecord>;
export const parse = parseAiaaicRow;
```

- Input: one CSV row object from the fingerprint pattern, or its JSON text. Not an object, or no `AIAAIC ID#`
  key → throw `aiaaic: …`.
- ID: `AIAAIC ID#` trimmed, must match `^AIAAIC\d+$`, else no records.
- Record `{ source: 'aiaaic', incidentId: <id>, kind: 'ai', title: <Incident headline>, date, entities, url }`:
  `date` only if `Occurred` is a full date (today it never is); `entities` from `Deployer`, `Developer`,
  `System name`, each split on `;`; `url` = `Summary/links` when http(s); no techniques.
- Known columns: the 20 header names above, including the empty name `''`. Any other key is unknown.

### 4. CFR Cyber Operations Tracker: `packages/parsers/src/cfr-cyber-ops.ts`

```ts
export function cfrIncidentId(title: string, date: string | null, affiliations: string): string;
export function parseCfrRow(input: unknown): ParseResult<IncidentRecord>;
export const parse = parseCfrRow;
```

- Input: one CSV row object, or its JSON text. Not an object, or no `Title` key → throw `cfr-cyber-ops: …`.
- `cfrIncidentId`: `<date or 'undated'>:<slug>:<hash>` where `slug` is the title lower-cased, runs of
  non-`[a-z0-9]` replaced by `-`, trimmed of `-`, cut to 60 characters (then trimmed of `-` again), and `hash`
  is the 8-hex-digit FNV-1a 32-bit hash of `title + '\u001f' + (date ?? '') + '\u001f' + affiliations` (raw
  trimmed cells). The hash keeps the two same-title, same-date rows apart. A comment says an edit to the
  title, date or affiliations gives a new ID (the CSV has none of its own).
- Record `{ source: 'cfr-tracker', incidentId, kind: 'cyber_op', title: <Title>, date: <Date>, entities, url }`:
  `entities` = `Sponsor` first (one name; commas belong to names like `Korea (Democratic People's Republic
  of)`), then `Affiliations` split on `,`, `;` and the word `and`, with a leading `Also known as` removed and
  a trailing `.` dropped; `url` = `Sources_1` when http(s), else `Sources_2`, else `Sources_3`; no
  techniques. `Victims`, `Description`, `Response`, `Type` and `Category` are known, not stored.
- Known columns: the twelve in the header above.

### 5. Source config

- `avid.ts`: `parser: 'avid'`, `pull.git = { repo: 'avidml/avid-db', branch: 'main', include:
  ['reports/20*/AVID-*.json', 'vulnerabilities/20*/AVID-*.json'] }`. A comment says `reports/review/` is left
  out (copies under review), and that the first run hands the archive to `first-load`, which does not unpack
  archives yet, so the backlog waits for that; new commits flow from the second run.
- `aiaaic.ts`: change `pattern` from `'heavy'` to `'fingerprint'` and drop `heavy: true` (966 KB and 2,259 rows
  fit a Worker step); `parser: 'aiaaic'`, `pull.fingerprint = { url:
  'https://docs.google.com/spreadsheets/d/1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI/export?format=csv&gid=888071280&range=A2:T',
  format: 'csv', key: 'AIAAIC ID#' }`. A comment says `range=A2:T` skips the banner row and the first run
  walks about 57 steps.
- `cfr-tracker.ts`: change `pattern` from `'page'` to `'fingerprint'`; `parser: 'cfr-cyber-ops'`,
  `pull.fingerprint = { url: 'https://static.cfr.org/cyber-operations/data/cyber-operations-incidents.csv',
  format: 'csv', key: 'Title' }`. A comment says `Title` repeats in 5 rows, so those rows are re-sent each run
  and link as unchanged (the parser's ID keeps them apart), and the first run walks about 23 steps.
- `mit-ai-risk.ts`, `csis.ts`, `umd-cissm.ts`: no `parser`, no `pull`; a comment gives the section 6 reason.

### 6. Sources left unwired (record in each `SOURCE.md` and source-file comment)

- **MIT AI Risk Repository.** The data is a Google Sheet whose ID changes with each release (V4 of 3 Dec 2025 is
  `15LeHcpeuZC9txkvcaMoh3sUhkMvdMMry69xxXL46DT0`, tab `gid=1710822211`, header on row 3, about 1.6 MB, CC BY 4.0),
  so no URL stays stable. Its rows are risk statements taken from papers (`Ev_ID` like `01.01.00`), not
  incidents, and `TechniqueRecord.framework` has no value for them. The MIT AI Incident Tracker is an Airtable
  embed with no export.
- **CSIS Significant Cyber Incidents.** The list is published as a PDF timeline, and the program page answers
  `403` (a bot challenge) to curl. No machine-readable feed.
- **UMD CISSM Cyber Events Database.** `cissm.umd.edu` now redirects to `gpi.umd.edu/cissm`; the database page
  (`/cissm/cissm-cyber-events-database`) answers `404`. The data was a dashboard with downloads on request. No
  public feed.

### 7. Fixtures (`fixtures/<source>/`, each folder with a `SOURCE.md`: URL, date, licence, real or hand-written)

Fetch each with curl in the sandbox and trim; hand-write a realistic equivalent only if the fetch fails, and
say so. Licence lines: AVID "MIT (repo LICENSE)"; AIAAIC and CFR "no licence checked here; source marked `ask`".

- `avid/AVID-2026-R1714.json` (0.3.3, with `impact.cwe`), `avid/AVID-2022-R0001.json` (0.1, `reported_date`
  only), `avid/AVID-2023-V028.json` (a vulnerability), all real from `raw.githubusercontent.com`.
- `aiaaic/incidents.csv`: the real ranged export trimmed to the header, the sub-header row and about 6
  incidents, including one with a range in `Occurred`, one with an empty `Occurred` and one with several
  `;`-separated developers.
- `cfr-tracker/incidents.csv`: the real header plus about 7 rows: the two Roshan rows, one with an empty `Date`,
  one with `Also known as …` affiliations, one with an empty `Sponsor`, and two ordinary rows.
- `mit-ai-risk/SOURCE.md`, `csis/SOURCE.md`, `umd-cissm/SOURCE.md` only: the check and why there is no pull.

### 8. Tests (`packages/parsers/test/`, Node, fixtures through `fixture()`)

- `ai-events.test.ts`:
  - **avid:** each fixture as an object, as JSON text and as a `GitFile` gives one `ai` record with the right
    ID, title, date (`published_date` for R1714, `reported_date` for R0001), entities (developers, deployers,
    artifact names, deduplicated), `techniques: ['CWE-506']` for R1714, and the URL rule for R and V IDs; a
    removed `GitFile` gives nothing; a bad ID gives nothing; an extra top-level field is reported; bad JSON throws.
  - **aiaaic:** run the fingerprint pattern's `fetch` (from `packages/patterns/src/fingerprint`) with `makeCtx`
    serving `incidents.csv` for the export URL; parse each item. One record per incident, no `date`, entities
    split on `;`, `url` the aiaaic.org page; the sub-header row never arrives; a non-object throws.
  - **cfr-cyber-ops:** the same through the pattern. The two Roshan rows give two different IDs; the undated
    row's ID starts `undated:`; `Also known as` is stripped; Sponsor comes first; `cfrIncidentId` is stable
    across calls and every ID matches the safe-ID rule; no record holds `Victims` or `Description` text.
- `sources-ai-events.test.ts`: each wired source's `parser` loads through `loadParser`; pull blocks and patterns
  equal section 5; `aiaaic` has no `heavy`; the three unwired sources have neither `parser` nor `pull`;
  licence and credit values equal main's; the three parser files contain no `node:` import, `Buffer`,
  `process.` or `require(`.
- `link-ai-events.test.ts`: the parsed fixtures through `link()` with `makeFake()` (as `link-sightings.test.ts`
  does): `incidents` rows keyed `(source, incident_id)` with kinds `ai` and `cyber_op`, JSON-list `entities`,
  `date` null for AIAAIC; linking the same records twice writes nothing the second time.

## Not in scope

- MIT AI Risk Repository, CSIS and UMD CISSM ingestion (section 6). `cyber_event` stays unused until one of
  them, or another event source, has a feed.
- The AVID backlog (needs `first-load` to unpack a GitHub archive); AIAAIC's Systems and Datasets tabs.
- A year or date-range field, a summary field or company keys (`domain:` / `cik:`) on `IncidentRecord`.
- Mapping AVID SEP/lifecycle codes, CFR `Type`/`Category` or AIAAIC harm taxonomies to techniques;
  `DATA_LICENSES.md`, the registry, patterns, linker, collector and API.

## Acceptance criteria

1. `pnpm build` passes (lint, typecheck, Node tests) and `pnpm test:workers` still passes.
2. `loadParser('avid')`, `loadParser('aiaaic')` and `loadParser('cfr-cyber-ops')` return modules whose `parse`
   returns `{ records, unknownFields }`.
3. The tests in section 8 pass using only fixtures; no test reaches the network.
4. `git diff --stat main` lists only the paths allowed in "What to build"; `pnpm-lock.yaml` and every
   `package.json` are unchanged; `rg "licence|credit"` over the six source files matches main.
5. Each fixture folder has a `SOURCE.md` saying where each file came from, when, and what was trimmed or
   hand-written; the three unwired folders record the check that failed.
6. Proof saved: `pnpm build` and `pnpm test:workers` output; one curl per wired URL (status, content type,
   size, and the first CSV line for AIAAIC and CFR); the GitHub tree count for the two AVID globs; the CSIS
   `403` and UMD `404`; the `link()` rows by table. The PR lists every endpoint check that failed or differed
   from this spec.
