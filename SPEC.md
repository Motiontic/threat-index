# parsers-breach-other: HIBP, CISA advisories and VCDB parsers and pull config

## Why

Three free sources describe breaches and government advisories outside the US notice regulators: Have I Been
Pwned lists verified breached datasets with account counts, CISA's advisory feed names the CVEs behind each ICS
and cybersecurity advisory, and the VERIS Community Database (VCDB) codes public breach reports into incidents.
Today `hibp`, `cisa-advisories` and `vcdb` have no `parser` and no `pull`, so the collector skips them with
"source has no pull config yet". This change writes one parser per source and fills in their pull config, so the
collector can run them on staging. Only metadata is kept: names, dates, counts, data types, CVE IDs and links,
never descriptions or analyst text. UK ICO is checked and left for later (see Not in scope).

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/sources/src/sources/hibp.ts` | `fingerprint`, `3h`, `on`, credit "Source: Have I Been Pwned (haveibeenpwned.com, CC BY 4.0)"; no `parser`, no `pull` |
| `cisa-advisories.ts` | `feed`, `3h`, `on`; default credit; no `parser`, no `pull` |
| `vcdb.ts` | `git`, `daily`, `ask`; default credit "Source: VCDB (VERIS)"; no `parser`, no `pull` |
| `uk-ico.ts` | `heavy`, `quarterly`, `on`, `heavy: true`, credit OGL v3.0; no `pull` |
| Parser contract | `loadParser(name)` imports `packages/parsers/src/<name>.ts`, which exports `parse(input)` returning `ParsedRecord[]` or `ParseResult<ParsedRecord>`. `apps/collector/src/step.ts` calls it once per `RawItem.body`; a throw counts that item as failed |
| `fingerprint` body | With no `itemsPath`, each body is one entry of the top-level JSON array (an object). The file is fetched whole every run when the server sends no validator; at most `MAX_FINGERPRINT_ITEMS` (5000) entries and `MAX_BODY_BYTES` (5 MiB); 40 changed items per step |
| `feed` body | The entry as `fast-xml-parser` gives it (`packages/patterns/src/feed.ts`, entities decoded, attributes as `@_name`), after `sanitizeLinks`: `{ title, link, description, pubDate, guid: { '#text', '@_isPermaLink' }, 'dc:creator' }`. The feed key is `guid` text |
| `git` body | `GitFile { path, status, previousPath?, text: string \| null }`. With no cursor the pattern hands off a `first-load` E2B job (that job is not built yet) |
| Records (`@ti/core/types`) | `NoticeRecord { source, noticeId, rawName, companyKey?, occurredFrom?, occurredTo?, discovered?, notified?, count?, countUnit, jurisdiction?, dataTypes?, url? }` with `countUnit` including `'accounts'`; `IncidentRecord { source, incidentId, kind: 'ai'\|'cyber_op'\|'cyber_event', title, date?, entities?, techniques?, url? }`; `AdvisoryRecord { source, sourceId, vulnKey, status, published?, modified, url?, affected? }` |
| Linker | Keeps a notice with `source`, `noticeId`, `rawName`, `countUnit`; an incident with `source`, `incidentId`, `title` and a valid `kind`. Dates must start `YYYY-MM-DD`. An advisory's IDs are `sourceId` then `vulnKey`, each must match `/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/`; a CVE among them becomes the hub. `advisories` has primary key `(source, source_id)` |
| Fixtures | `fixtures/cisa-advisories/` holds `pattern-all.xml` and `PATTERNS.md` for the feed pattern tests; keep them. No `fixtures/hibp/` or `fixtures/vcdb/` yet |

Endpoints, checked on 24 Nov 2026 with curl:

- `https://haveibeenpwned.com/api/v3/breaches`: 200, `application/json`, 1.14 MB, 1,055 breaches, no ETag or
  Last-Modified (`cache-control: public, max-age=300`), no key needed. Every entry has the same 20 keys: `Name`,
  `Title`, `Domain`, `BreachDate` (`YYYY-MM-DD`), `AddedDate`, `ModifiedDate` (ISO, `Z`), `PwnCount`,
  `Description` (HTML), `LogoPath`, `Attribution`, `DisclosureUrl`, `DataClasses` (string array), and the flags
  `IsVerified`, `IsFabricated`, `IsSensitive`, `IsRetired`, `IsSpamList`, `IsMalware`, `IsSubscriptionFree`,
  `IsStealerLog`. Counts: 42 unverified, 3 fabricated, 16 spam lists, 96 sensitive, 2 retired, 10 malware, 6
  stealer logs, 55 with an empty `Domain`. `Name` holds only letters, digits and `-`.
- `https://haveibeenpwned.com/api/v3/latestbreach`: 200, one breach object, same shape.
- `https://haveibeenpwned.com/Breach/<Name>`: 200 HTML page per breach.
- `https://www.cisa.gov/cybersecurity-advisories/all.xml`: 200, `application/rss+xml`, ~367 KB, no ETag, 30
  items newest first (about 18 days). `guid` is `/node/<n>` (`isPermaLink="false"`), not the advisory ID.
  `pubDate` has a two-digit year: `Mon, 23 Nov 26 12:00:00 +0000`. `description` is the whole advisory as
  escaped HTML (up to ~40 KB) and names its CVEs in the text. Links seen: `/news-events/ics-advisories/icsa-26-323-02`,
  `/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching`, KEV announcements
  (`/news-events/alerts/…/cisa-adds-two-known-exploited-vulnerabilities-catalog`) and
  `/resources-tools/resources/…` pages with no CVE.
- `vz-risk/VCDB` on GitHub: default branch `master`, `LICENSE.txt` is CC BY-SA 4.0. Incidents are one JSON file
  each under `data/json/validated/` and `data/json/submitted/`; recent commits add 60–160 files to `submitted/`.
  A file is a VERIS 1.4 incident: `incident_id` (upper-case UUID), `security_incident` (`Confirmed`, …),
  `reference` (URL), `summary`, `timeline.incident { year, month?, day? }`, `victim { victim_id, country[],
  state?, industry }`, `action { hacking|malware|social|misuse|physical|error|environmental|Unknown: { variety[] } }`,
  `attribute`, `plus { github, analyst, analyst_notes, … }`.

## What to build

Touch only: new `packages/parsers/src/{hibp,cisa-advisories,vcdb}.ts`, new tests under `packages/parsers/test/`,
new `fixtures/hibp/`, `fixtures/vcdb/`, new files in `fixtures/cisa-advisories/` (keep `pattern-all.xml` and
`PATTERNS.md`), and `packages/sources/src/sources/{hibp,cisa-advisories,vcdb}.ts`. No shared contract files, no
linker, pattern or collector changes, no migrations, no new dependencies (`zod` is already there). No Node-only
imports: the same code runs in Workers and E2B.

Every parser accepts its pattern's body, a JSON string of it, or (VCDB) a `GitFile`; bad JSON, a non-object or a
missing or invalid ID throws. Unknown keys are reported in `unknownFields` by name and never throw.

### 1. `packages/parsers/src/hibp.ts`

```ts
export const MAX_DATA_TYPES = 30;
export function parseHibp(input: unknown): ParseResult<NoticeRecord>;
export const parse = parseHibp;
```

- Validate with zod (`looseObject`): `Name` matching `/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/`, `Title` string,
  `PwnCount` a non-negative integer, `DataClasses` string array, the eight `Is*` flags booleans. Missing or wrong
  → throw.
- **Skip** (return no records) when any of: `IsVerified` false, `IsFabricated`, `IsSpamList`, `IsSensitive`,
  `IsRetired`, `IsMalware`, `IsStealerLog`. Spam lists, stealer logs and malware dumps have no breached company;
  unverified and fabricated ones may not be real; sensitive ones are kept out on purpose.
- **One `NoticeRecord`:** `source: 'hibp'`; `noticeId: Name`; `rawName: Title` trimmed (fall back to `Name`);
  `occurredFrom: BreachDate` when it is a valid `YYYY-MM-DD` date, else left out; `count: PwnCount`;
  `countUnit: 'accounts'`; `dataTypes`: `DataClasses` trimmed, unique, first `MAX_DATA_TYPES`;
  `url: https://haveibeenpwned.com/Breach/<Name>`. Leave out `companyKey`, `notified`, `discovered`,
  `jurisdiction` (HIBP's `AddedDate` is when HIBP loaded the data, not a notification date).
- Never keep `Description`, `LogoPath`, `Attribution` or `DisclosureUrl`.
- Unknown fields: top-level keys outside the 20 listed above.

### 2. `packages/parsers/src/cisa-advisories.ts`

```ts
export const MAX_CVES_PER_ADVISORY = 100;
export function advisoryId(link: string, guid: string): string | null;
export function parseCisaAdvisory(input: unknown): ParseResult<AdvisoryRecord>;
export const parse = parseCisaAdvisory;
```

- Read `title`, `link`, `description`, `pubDate` and `guid` with `textOf`-style helpers (a value may be a string
  or `{ '#text': … }`). Do not import `@ti/patterns`.
- **Which items.** Keep items whose link path starts with `/news-events/ics-advisories/`,
  `/news-events/ics-medical-advisories/`, `/news-events/cybersecurity-advisories/` or `/news-events/alerts/`, on
  host `www.cisa.gov`. Skip alerts whose title matches `/^CISA Adds .* Known Exploited Vulnerabilit/i` (the
  `cisa-kev` source already carries those) and every other path (`/resources-tools/…`, news). Skipped → no records.
- **`advisoryId`.** The last link path segment, upper-cased, when it matches
  `/^(icsa|icsma)-\d{2}-\d{3}-\d{2}[a-z]?$/i` or `/^aa\d{2}-\d{3}[a-z]$/i`; otherwise `CISA-<n>` from a guid
  `/node/<n>`; otherwise `null`, and the parser throws.
- **Date.** Parse `pubDate` as RFC 822 by regex (optional weekday, day, English month, two- or four-digit year
  where `yy` means `20yy`, `HH:MM[:SS]`, zone `+hhmm`/`-hhmm`/`GMT`/`UTC`/`Z`) to UTC
  `YYYY-MM-DDTHH:MM:SS.000Z`. Do not rely on `Date.parse` for two-digit years. Invalid → throw.
- **CVEs.** Every match of `/CVE-\d{4}-\d{4,}/gi` in `title` then `description`, normalised with `normaliseId`,
  unique, in first-seen order, first `MAX_CVES_PER_ADVISORY`. No CVE → no records.
- **One `AdvisoryRecord` per CVE:** `source: 'cisa-advisories'`; `sourceId: '<advisoryId>:<CVE>'` (one row per
  advisory and CVE under the `(source, source_id)` key); `vulnKey: <CVE>`; `status: 'active'`;
  `published` = `modified` = the date; `url` = the link. Never keep `description` text.
- Unknown fields: item keys outside `title`, `link`, `description`, `pubDate`, `guid`, `dc:creator`, `category`.

### 3. `packages/parsers/src/vcdb.ts`

```ts
export const MAX_TITLE = 200;
export function parseVcdb(input: unknown): ParseResult<IncidentRecord>;
export const parse = parseVcdb;
```

- Input: a `GitFile` (`text: null` or `status: 'removed'` → no records), a JSON string or an object.
- `incident_id` must match `/^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/`, else throw.
- **Skip** unless `security_incident === 'Confirmed'`.
- **One `IncidentRecord`:** `source: 'vcdb'`; `incidentId`: `incident_id` upper-cased; `kind: 'cyber_event'`;
  `title`: `<victim>: <Action> (<first variety>)` as `"NAS Recovery Solutions: Misuse (Privilege abuse)"`, where
  victim is `victim.victim_id` (or `Unnamed organisation` when empty or `Unknown`), Action is the first `action`
  key in the order hacking, malware, social, misuse, physical, error, environmental, capitalised, and the variety is
  left out when missing or `Unknown`; no action → `"<victim>: incident"`; cut to `MAX_TITLE`.
  `date`: `YYYY-MM-DD` only when `timeline.incident` has a valid year, month and day; otherwise left out (no
  invented precision). `entities`: `[victim_id]` when named. `url`: the first http(s) URL in `reference` (split on
  whitespace, `;` and `,`), else `https://github.com/vz-risk/VCDB/issues/<plus.github>` when that is all digits,
  else left out. Leave out `techniques` (VERIS to ATT&CK mapping is later work).
- Never keep `summary`, `notes`, `discovery_notes`, `plus.analyst*` or any free text.
- Unknown fields: top-level keys outside `schema_version`, `schema_name`, `incident_id`, `source_id`,
  `reference`, `security_incident`, `confidence`, `summary`, `related_incidents`, `notes`, `victim`, `actor`,
  `action`, `asset`, `attribute`, `timeline`, `discovery_method`, `discovery_notes`, `targeted`, `impact`,
  `plus`, `cost_corrective_action`, `control_failure`, `corrective_action`, `value_chain`, `campaign_id`.

### 4. Source config

Set `parser` and `pull` (and the VCDB credit). Change no other field, and never the licence.

| Source | `parser` | `pull` |
| ------ | -------- | ------ |
| `hibp` | `hibp` | `fingerprint: { url: 'https://haveibeenpwned.com/api/v3/breaches', format: 'json', key: 'Name' }` |
| `cisa-advisories` | `cisa-advisories` | `feed: { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', order: 'newest-first' }` |
| `vcdb` | `vcdb` | `git: { repo: 'vz-risk/VCDB', branch: 'master', include: ['data/json/validated/*.json', 'data/json/submitted/*.json'] }` |

`vcdb` credit: `'Source: VERIS Community Database (vz-risk/VCDB, CC BY-SA 4.0)'`. Add a one-line comment in
`hibp.ts`: the server sends no validator, so each run downloads the ~1.1 MB list and diffs it by `Name`; the
first run spreads ~1,000 changed entries over about 25 steps. Add one in `vcdb.ts`: the first run hands off a
`first-load` job, which loads nothing until that E2B job exists.

Before committing, check each URL from the sandbox with `curl -sI` (for VCDB, `https://api.github.com/repos/vz-risk/VCDB`)
and save the status lines as proof. If the sandbox cannot reach a host, say so in the PR; don't guess.

### 5. Fixtures

Fetch real data with `curl` and trim it; when a host is unreachable, hand-write files of the same shape and say
so. Each new folder gets a `SOURCE.md` (URL, fetch date, licence, what was trimmed).

- `fixtures/hibp/breaches.json`: an array of 8 real entries from `/api/v3/breaches`, `Description` cut to 200
  characters: `Adobe`, `Bromcom`, `AllegedATT` (empty `Domain`), `AdultFriendFinder` (sensitive), `Acuity` (spam
  list), `JustDate` (fabricated), `126` (unverified), `AlienStealerLogs` (stealer log). `latestbreach.json` from
  `/latestbreach`. Hand-written `bad.json` (no `Name`) and `extra-key.json` (one valid entry plus `IsNewFlag`).
- `fixtures/cisa-advisories/all.xml`: the real feed trimmed to 5 items, each `description` cut to ~1,500
  characters but keeping its CVE IDs: one ICS advisory with 1 CVE (`icsa-26-323-03`), one with 6
  (`icsa-26-321-01`), the Java alert (`/node/25817`, 1 CVE), a KEV announcement and a `/resources-tools/` item.
  Hand-written `aa-advisory.xml`: one `aa26-310a` item with a four-digit-year `pubDate` and 120 CVEs.
- `fixtures/vcdb/`: two real files from `data/json/submitted/` (one with full day, one with only year and month),
  hand-written `suspected.json` (`security_incident: 'Suspected'`), `no-victim.json` (`victim_id: 'Unknown'`, no
  `reference`, `plus.github: '23768'`) and `bad-id.json`.

### 6. Tests (`packages/parsers/test/breach-other.test.ts`, `sources-breach-other.test.ts`; Node, no network)

- HIBP: `breaches.json` entry by entry gives exactly 3 notices (`Adobe`, `Bromcom`, `AllegedATT`) with
  `countUnit: 'accounts'`, `count`, `occurredFrom`, `url` and `dataTypes` checked; the five flagged entries give
  none; `bad.json` throws; `extra-key.json` lists `IsNewFlag`; a JSON string and an object give equal output.
- CISA: the five items (as the `feed` pattern would pass them; build them with `parseFeed` from
  `packages/patterns/src/feed` and `sanitizeLinks`, as the OSV tests import pattern code) give 1 + 6 + 1 records
  and none for the KEV announcement and the resource; `sourceId` is `ICSA-26-323-03:CVE-…` and `CISA-25817:CVE-…`;
  `published` is `2026-11-19T12:00:00.000Z` for a `… 26 12:00:00 +0000` date; `aa-advisory.xml` gives exactly
  `MAX_CVES_PER_ADVISORY` records with `AA26-310A:` ids; an item with no ID and no `/node/` guid throws.
- VCDB: each fixture as a `GitFile`, a JSON string and an object gives equal output; `title`, `date` (present only
  for the full-date file), `entities`, `url` checked; `suspected.json` and a removed `GitFile` give none;
  `bad-id.json` throws; no record contains the `summary` text.
- `loadParser` resolves `hibp`, `cisa-advisories` and `vcdb`.
- `sources-breach-other.test.ts`: for the three sources (from `SOURCE_BY_ID`) the parser loads, the `pull` block
  matches the source's pattern, and the licences are still `hibp: on`, `cisa-advisories: on`, `vcdb: ask`, with
  `uk-ico` unchanged. Run the `fingerprint` pattern's `fetch()` for `hibp` and the `feed` pattern's `fetch()` for
  `cisa-advisories` against the fixtures through the pattern test helpers (stub `fetch`), parse every returned
  item body, and check the record counts above.

## Not in scope

- **UK ICO.** The only stable public data is the data security incident trends CSV (~38 MB, ~237,000 rows, Q1
  2019 to Q3 2026), whose URL changes every quarter (`/media2/<random>/data-security-incidents-trends-download-q1-2019-to-q3-2026.csv`).
  Its rows are anonymised (sector, incident type, size band, quarter) with no organisation, so they fit none of
  the record types; they need a statistics table, a page step to find the current link, and a `big-file` job.
  The enforcement list is rendered by JavaScript. `uk-ico.ts` is not touched.
- HIBP domains: `NoticeRecord` has no domain field, so `Domain` is not carried; company matching by domain needs
  a contract change first. HIBP's `/latestbreach` shortcut and per-breach fetches.
- VCDB breach notices from `attribute.confidentiality.data_total`, VERIS to ATT&CK techniques, other VCDB fields.
- CISA CSAF files (`cisagov/CSAF`), affected products, advisory revisions, KEV announcements, non-CVE advisories.
- The `first-load` job, any change to patterns, the collector, the linker, the registry, shared types or other
  sources.

## Acceptance criteria

1. `pnpm build` (lint, typecheck, `pnpm test`) and `pnpm test:workers` pass; save both outputs.
2. `hibp.ts`, `cisa-advisories.ts` and `vcdb.ts` export the names and signatures in sections 1–3.
3. The tests in section 6 pass on fixtures only; no test makes a network request.
4. `git diff --stat main -- packages/sources/src` shows only the three source files, and in each only `parser`,
   `pull`, a comment and (VCDB) `credit` changed; paste the diff in the PR.
5. No parser output carries free text: a test asserts that no HIBP `Description`, CISA `description` or VCDB
   `summary` substring appears in any record.
6. Proof saved: the `curl` status lines for every URL in section 4 (or a note that the host was unreachable), and
   a table of fixture → records produced (count, kind, key fields).
7. No Node-only import under `packages/parsers/src` (`rg "from 'node:" packages/parsers/src` is empty).

## Coordination with work built at the same time

- Company hints use the linker's format in the existing `companyKey` field: `domain:<host>` for HIBP's
  `Domain` (lowercase, no `www.`), `cik:<digits>` where a CIK is known. Any other value is ignored. Set
  `jurisdiction` as an ISO code (for example `US-CA`) when known.
- Skipping HIBP's sensitive breaches is the right call. Keeping VCDB's licence at `ask`, with metadata-only
  rows and an updated credit, is fine.
