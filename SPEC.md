# parsers-cve-nvd: parse CVE JSON 5, NVD 2.0 and the MITRE CWE/CAPEC catalogues, and wire their sources

## Why

The collector runs every source on its cadence, but the four sources that carry the core vulnerability
record have no `pull` block and no parser, so each run ends as `skipped: source has no pull config yet`.
This change adds the three parsers from `docs/IMPLEMENTATION_PLAN.md` §4 (`@ti/parsers`: CVE JSON 5 with
CNA and ADP/Vulnrichment data, NVD 2.0, and the CWE catalogue, with CAPEC in the same module) and fills
`parser` and `pull` in the CVE List, NVD, CWE and CAPEC source files, so the collector pulls them on staging.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/parsers/src/cve-json5.ts`, `nvd.ts` | Stubs: `parse(_input): ParsedRecord[]` throws `NotImplementedError` |
| `packages/parsers/src/cwe.ts` | Does not exist |
| `packages/parsers/src/kev.ts` | The model to copy: Zod `looseObject`, known-field set, `ParseResult` + `unknownFields`, `export const parse` |
| `packages/parsers/src/load.ts` | `loadParser(name)` imports `./<name>.ts`; a module must export `parse(input) → ParsedRecord[] \| ParseResult<ParsedRecord>` |
| `packages/parsers/package.json` | Deps: `@ti/core`, `@ti/sources`, `zod`. No XML library (`fast-xml-parser` belongs to `@ti/patterns`) |
| Source files | `cve-list.ts` (git, 3h), `cisa-vulnrichment.ts` (git, with-cve-list), `nvd.ts` (since, 3h, credit `NVD_NOTICE`), `cwe.ts` and `capec.ts` (heavy, weekly, `heavy: true`). All licence `on`. None has `parser` or `pull` |
| `packages/patterns/test/examples.ts` | Worked `pull` blocks for `cve-list`, `nvd` and `cwe`, meant to be copied into the source files |
| Pattern item bodies | `git`: a `GitFile { path, status, previousPath?, text }` per changed file (`text` is null for a removed file). `since`: the whole response with its items array cut to one entry. `heavy`: no items; the collector hands the job to E2B before any parser runs |
| `packages/linker` | Tells records apart by fields (`kinds.ts`). `CVE_HOME_SOURCE = 'cve-list'` owns title, summary and published on a CVE hub. CVSS belongs to the first scorer (`cvssSource ?? source`). `kev_added` is set only by an `exploited_wild` signal from `cisa-kev`. `packages/linker/src/testing/fake-deps.ts` has `makeFake()` |
| Credits | `apps/api/src/lib/credits.ts` builds credits from each record's `source` through `SourceConfig.credit`; `nvd` adds `NVD_NOTICE` |
| Fixtures | `fixtures/{cve-list,nvd,cwe}/` hold only `pattern-*` files and `PATTERNS.md` for the pattern tests. Leave those files as they are |

## What to build

Touch only: `packages/parsers/src/{cve-json5,nvd,cwe}.ts`, new tests in `packages/parsers/test/`, new files
under `fixtures/{cve-list,cisa-vulnrichment,nvd,cwe,capec}/`, and the source files
`packages/sources/src/sources/{cve-list,cisa-vulnrichment,nvd,cwe,capec}.ts`. No dependency changes, no
change to `pnpm-lock.yaml`, `load.ts`, `kev.ts`, the registry, patterns, linker, apps or migrations. Never
change a `licence` value or a `credit`.

### 1. Shared rules for all three parsers

- Each module exports a named parser and `export const parse = <named>`, returning
  `ParseResult<ParsedRecord>` with records in the shapes of `@ti/core/types`.
- Worker-safe: no `node:` imports, no `Buffer`, `fs`, `process` or `require`. Validate with Zod
  `z.looseObject` like `kev.ts`.
- Input may be an object or a JSON/XML string (CVE JSON 5 also accepts a `GitFile`, section 2).
- A malformed document throws an `Error` whose message starts with the parser name
  (`cve-json5: …`). The collector counts it as one failed item, so never throw for a single odd field.
- Unknown fields go into `unknownFields` as dotted paths (`cna.newField`, `cve.newField`), each at most
  once, never a crash.
- IDs through `normaliseId` from `@ti/core/ids`. `modified` is `new Date(x).toISOString()` (the linker
  compares strings for "newer wins"). NVD timestamps carry no zone; they are UTC, so append `Z` first.
- `summary` is the first English description, whitespace collapsed, cut to 300 characters at a word
  boundary. `title` is at most 200 characters.
- CVSS: one score per record. Prefer v3.1, then 4.0, then 3.0, then 2.0, so the stored score keeps the
  same meaning across sources. `cvssVersion` is `'3.1'`, `'4.0'`, `'3.0'` or `'2.0'`.

### 2. CVE JSON 5: `packages/parsers/src/cve-json5.ts`

```ts
export function parseCveRecord(input: unknown): ParseResult<ParsedRecord>;
export const parse = parseCveRecord;
```

- Input: a `GitFile` from the `git` pattern (parse its `text`; a `removed` file or `text: null` returns
  no records), a CVE record object, or its JSON text. Recognise a `GitFile` by its shape (`path`,
  `status`, `text`); don't import `@ti/patterns`, which is not a dependency of `@ti/parsers`. `dataType` must be `CVE_RECORD`; `dataVersion`
  `5.x` (5.0 to 5.2 at least).
- `PUBLISHED`, from the CNA container, one `VulnRecord` with `source: 'cve-list'`, `kind: 'cve'`,
  `key` the CVE ID, `aliases: []`:
  - `title`: `cna.title`, else the first sentence of the summary (≤ 120 chars), else the CVE ID;
  - `published`: `cveMetadata.datePublished`; `modified`: `dateUpdated`, else `datePublished`;
  - `cvss`, `cvssVersion` from `cna.metrics` (`cvssV3_1`, `cvssV4_0`, `cvssV3_0`, `cvssV2_0` →
    `baseScore`), `cvssSource` = `cveMetadata.assignerShortName`;
  - `cwe`: every `problemTypes[].descriptions[].cweId` matching `^CWE-\d+$`, unique.
- `REJECTED`: one `VulnRecord` (title `<ID> (rejected)`, summary from `cna.rejectedReasons`, no CVSS)
  and one `AdvisoryRecord { source: 'cve-list', sourceId: <ID>, vulnKey: <ID>, status: 'rejected',
  modified, url: 'https://www.cve.org/CVERecord?id=<ID>' }`.
- CISA Vulnrichment. In cvelistV5, CISA's ADP data sits in `containers.adp[]` where
  `providerMetadata.shortName === 'CISA-ADP'`. From that container only, attributed to
  `source: 'cisa-vulnrichment'`:
  - SSVC (`metrics[].other.type === 'ssvc'`; `content.options` is a list of one-key objects; match
    `Exploitation` without regard to case): `active` → `SignalRecord { kind: 'exploited_wild',
    ref: 'ssvc', firstSeen: <content.timestamp as date> }`; `poc` → the same with `kind: 'poc'`;
    `none` → nothing. Signals stay separate from KEV: this never sets `kev_added`.
  - CVSS or CWE from that container → one `VulnRecord` with `source: 'cisa-vulnrichment'`,
    `cvssSource: 'CISA-ADP'`, title the CVE ID and empty summary (the linker keeps the CNA's text),
    `modified` from the container's `providerMetadata.dateUpdated`.
  - The ADP `kev` entry is read but not emitted: KEV belongs to the `cisa-kev` source.
- Other ADP containers (the CVE Program's `CVE` container of references) are ignored and are not
  unknown fields. `affected`, `references` and `configurations` are known fields not mapped in this
  change.

### 3. NVD 2.0: `packages/parsers/src/nvd.ts`

```ts
export function parseNvd(input: unknown): ParseResult<ParsedRecord>;
export const parse = parseNvd;
```

- Input: a CVE API 2.0 response (`{ vulnerabilities: [{ cve }] }`, any length; the `since` pattern
  sends it cut to one entry) or a single `{ cve }`.
- Per `cve`: `vulnStatus === 'Rejected'` → one `AdvisoryRecord { source: 'nvd', sourceId: id,
  vulnKey: id, status: 'rejected' }` and nothing else. Otherwise one `VulnRecord` with
  `source: 'nvd'`, `kind: 'cve'`, `title` = `cisaVulnerabilityName`, else the summary's first sentence,
  `published`, `modified` = `lastModified`, and:
  - CVSS only from metrics with `type: 'Primary'` (NVD's own analysis), keys `cvssMetricV31`,
    `cvssMetricV40`, `cvssMetricV30`, `cvssMetricV2` → `cvssData.baseScore`; `cvssSource: 'nvd'`.
    Secondary (CNA-copied) scores are skipped; the CNA's score arrives through `cve-list`.
  - `cwe` from `weaknesses[].description[].value` matching `^CWE-\d+$` (`NVD-CWE-Other` and
    `NVD-CWE-noinfo` dropped).
- Known, not mapped: `configurations`, `references`, `cveTags`, `vendorComments`, `evaluator*`,
  `cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction` (KEV belongs to `cisa-kev`).
- Every NVD record has `source: 'nvd'`, so the API's credit for any entry built from it includes
  `NVD_NOTICE` ("This product uses the NVD API but is not endorsed or certified by the NVD.").
  Keep `credit: NVD_NOTICE` in `sources/nvd.ts`.

### 4. CWE and CAPEC: `packages/parsers/src/cwe.ts`

```ts
export function parseMitreCatalog(input: unknown): ParseResult<TechniqueRecord> & { version: string };
// input must be the XML text; anything else throws `cwe: expected XML text`
export const parse = parseMitreCatalog;
```

- One module for both MITRE XML catalogues, chosen by the root element: `Weakness_Catalog` (CWE) or
  `Attack_Pattern_Catalog` (CAPEC); any other root throws. `version` is the root's `Version` attribute.
- No XML library may be added, so write a small scanner: find each `<Weakness …>` / `<Attack_Pattern …>`
  element, read its attributes, its `<Description>` text (tags stripped, the five XML entities and
  numeric references decoded) and its `Related_Weakness` / `Related_Attack_Pattern` children.
- Records: `TechniqueRecord { id: 'CWE-<ID>' | 'CAPEC-<ID>', framework: 'cwe' | 'capec', name,
  summary (≤ 300), parent }`. `parent` is the `ChildOf` relation: for CWE the one with
  `View_ID="1000"` and `Ordinal="Primary"`, else the first `ChildOf`; for CAPEC the first `ChildOf`.
- Skip entries with `Status="Deprecated"`. Categories and views are not emitted in this change.
- This parser runs in the E2B big-file job, not in a Worker (the collector hands `heavy` sources off
  before parsing). Keep it Worker-safe anyway; on a 15 MB catalogue it must finish in under 5 seconds
  in Node (test with a fixture repeated in memory, not a large committed file).

### 5. Source config

Copy the worked blocks from `packages/patterns/test/examples.ts` and check each endpoint against its
current docs (record the URLs and the date checked in the fixture folder's `SOURCE.md`):

- `cve-list.ts`: `parser: 'cve-json5'`, `pull.git = { repo: 'CVEProject/cvelistV5', branch: 'main',
  include: ['cves/*/*/CVE-*.json'] }`. The narrower glob keeps `cves/delta.json` and
  `cves/deltaLog.json` out (the worked example's `cves/**/*.json` matches them). A first run with no
  cursor becomes a `first-load` job, which another change implements.
- `cisa-vulnrichment.ts`: no `pull` in this change. Its data reaches us inside cvelistV5 records
  (section 2) and is attributed to it. Pulling `cisagov/vulnrichment` as well would read every record
  twice. Add a comment saying so; set `parser: 'cve-json5'` so a later git pull needs no parser work.
- `nvd.ts`: `parser: 'nvd'`, the worked `since` block (`https://services.nvd.nist.gov/rest/json/cves/2.0`,
  `lastModStartDate` / `lastModEndDate`, `startIndex`, `resultsPerPage`, `vulnerabilities`, `cve.id`,
  `totalResults`, `maxWindowDays: 120`, `auth: { header: 'apiKey', credential: 'nvd' }`) plus
  `lookbackDays: 7`, and `rateLimit: { perMinute: 8 }` (NVD allows 5 requests per 30 s without a key).
  The key is optional: without `NVD_API_KEY` the pattern sends no header. Backfilling all of NVD is a
  later first-load job; `cve-list` is the home record.
- `cwe.ts`: `parser: 'cwe'`, `pull.heavy = { url: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
  version: { url: 'https://cwe.mitre.org/data/downloads.html', pattern: <regex matching the page> } }`.
- `capec.ts`: `parser: 'cwe'`, `pull.heavy = { url: 'https://capec.mitre.org/data/xml/capec_latest.xml',
  version: { url: <same file>, pattern: 'Version="([\\d.]+)"', bytes: 2048 } }` (the root element near
  the top of the file carries the version).
- With internet in the sandbox, `curl` each URL once to confirm it (status, the version regex matches,
  and that NVD accepts `toISOString()` dates such as `2026-11-20T00:00:00.000Z`). Save the output. If a
  check fails, say so in the PR; don't change `packages/patterns` to fix it.

### 6. Fixtures (`fixtures/<source>/`, each folder with a `SOURCE.md`: URL, date, licence, real or hand-written)

- `cve-list/CVE-2024-3400.json`: a real record (`curl` from
  `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/3xxx/CVE-2024-3400.json`), with
  CNA CVSS 3.1 and 4.0 and a `CISA-ADP` container holding SSVC `active` and KEV. Hand-write a
  realistic equivalent if the fetch fails, and say so.
- `cve-list/rejected.json`, `cve-list/adp-only.json` (CNA without metrics, CISA ADP with CVSS 3.1, CWE
  and SSVC `poc`): hand-written.
- `cisa-vulnrichment/SOURCE.md` only, pointing at the cve-list fixtures.
- `nvd/CVE-2024-3400.json` (an API response for `?cveId=CVE-2024-3400`, real or realistic, with a
  Primary and a Secondary metric) and `nvd/rejected.json`.
- `cwe/cwec-sample.xml` (CWE-74, CWE-79 child of 74, CWE-89, one deprecated, one category) and
  `capec/capec-sample.xml` (CAPEC-66 child of 248, CAPEC-248, one deprecated). Hand-written, trimmed.

### 7. Tests (`packages/parsers/test/`, Node, read fixtures with `fixture()` from `test/fixtures.ts`)

- `cve-json5.test.ts`: the published record gives the expected vuln (v3.1 score, CWE, title, ISO
  `modified`), an SSVC `exploited_wild` signal from `cisa-vulnrichment`, and no KEV signal; the
  `GitFile` form gives the same records; a removed `GitFile` gives none; rejected → vuln + `rejected`
  advisory; ADP-only → a `cisa-vulnrichment` vuln with `cvssSource: 'CISA-ADP'` and a `poc` signal; a
  new field lands in `unknownFields`; bad JSON and a non-CVE document (`delta.json` shape) throw.
- `nvd.test.ts`: Primary score taken, Secondary skipped; `NVD-CWE-*` dropped; zoneless dates become
  `…Z`; rejected → advisory only; a response with several entries; unknown field reported.
- `cwe.test.ts`: CWE and CAPEC records, parents, entity decoding, deprecated skipped, version read,
  wrong root throws, and the timing check from section 4.
- `sources-cve-nvd.test.ts`: each covered source's `parser` loads through `loadParser`; the pull blocks
  equal section 5; licence and credit values equal those on main; `nvd`'s credit is `NVD_NOTICE`; the
  three parser files contain no `node:` import, `Buffer`, `process.` or `require(`.
- `link-cve-nvd.test.ts`: parsed fixture records go through `link()` with `makeFake()` (import by
  relative path from `packages/linker/src/`; if typecheck refuses that, run it as a script and save the
  output instead). Check: one `vulns` row for CVE-2024-3400 whose `sources` include `cve-list`, `nvd`
  and `cisa-vulnrichment`, title from `cve-list`, `kev_added` still null, a `signals` row from
  `cisa-vulnrichment`, and `techniques` rows from the CWE sample.

## Not in scope

- Pulling the `cisagov/vulnrichment` repo, first-load jobs (cvelistV5 archive, NVD backfill) and the
  E2B big-file job that will call `cwe`. Mapping `affected`, `configurations` (CPE) and references into
  advisories. CWE categories and views, `vuln_techniques` rows.
- Any change to patterns, the linker, the collector, `load.ts`, the registry or another source.

## Acceptance criteria

1. `pnpm build` passes (lint, typecheck, Node tests) and `pnpm test:workers` still passes.
2. `loadParser('cve-json5')`, `loadParser('nvd')` and `loadParser('cwe')` return modules whose `parse`
   returns `{ records, unknownFields }`; no `NotImplementedError` remains in those three files.
3. The tests in section 7 pass, using only fixtures (no network in tests).
4. `git diff --stat main` lists only the paths allowed in "What to build"; `pnpm-lock.yaml` and every
   `package.json` are unchanged; `rg "licence:" packages/sources/src/sources/{cve-list,cisa-vulnrichment,nvd,cwe,capec}.ts`
   shows no change from main.
5. Each fixture folder has a `SOURCE.md` saying where each file came from and when.
6. Proof saved: `pnpm build` and `pnpm test:workers` output; the `curl` checks from section 5; the
   `link()` result for CVE-2024-3400 (rows by table); and the PR states which fixtures are real and which
   hand-written, and every endpoint check that failed.
