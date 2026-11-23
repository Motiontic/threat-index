# parsers-breach-us: SEC 8-K Item 1.05, HHS OCR, California AG and Washington AG notice parsers and pull config

## Why

Breach notices are the first thing a buyer checks about a vendor: "has this company told a regulator it was
breached, when, and how many people?" Four US sources answer it, but their source files have no `parser` and
no `pull`, so the collector skips them (`source has no pull config yet`). This change adds one parser per
source, each emitting `NoticeRecord`s with a count and its unit (never summed across units), the dates the
notice gives, and a `companyKey` hint where the source has a real identifier (the SEC CIK). It fills the pull
config so the collector runs them on staging. Company matching and grouping notices into breach events is
separate work in `packages/linker`; these parsers only report what each notice says.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| Source files | `sec-edgar.ts` (feed, 3h, `on`), `hhs-ocr.ts` (fingerprint, daily, `on`), `ca-ag.ts` (fingerprint, daily, `ask`), `wa-ag.ts` (since, daily, `ask`), `state-ags.ts` (page, daily, `ask`). None has `parser` or `pull` |
| `NoticeRecord` (`packages/core/src/types.ts`) | `source, noticeId, rawName, companyKey?, occurredFrom?, occurredTo?, discovered?, notified?, count?, countUnit, jurisdiction?, dataTypes?, url?`. `CountUnit` = `state_residents \| individuals \| accounts \| not_stated \| claim` |
| Linker | Keeps a notice only with `source`, `noticeId`, `rawName`, `countUnit`. `noticeRow` keeps ISO dates, an integer count, an http(s) `url`. `noticeChange` raises `breach_notice` only when `companyKey` is set |
| `feed` pattern | One item per Atom entry; body is the fast-xml-parser node (`title`, `link {@_href}`, `summary {#text}`, `updated`, `category {@_term}`, `id`), links sanitised. Cursor = newest entry `id` |
| `page` pattern | `HTMLRewriter` (Workers only). `item` selector starts a row; `fields` fill it (text, or `{selector, attr}`); fields named `link`/`url` are made absolute, non-http dropped. Body = `Record<string,string>`; `key` names the field used as item id and cursor |
| `fingerprint` pattern | Whole JSON/CSV file, diffed by `key` per entry hash; ≤ 5,000 entries; body = the entry object |
| `since` pattern | Sets `startParam`/`endParam` to ISO timestamps as separate query parameters. Socrata needs a `$where` clause, so it does not fit |
| User-Agent | Every request sends `ctx.userAgent`. Production sets a contact; the staging value has only the repo URL |
| Model parsers | `kev.ts` (Zod `looseObject`, known-field set), `exploit-db.ts` (`isoDay`), parsers export `parse` |

Endpoints, checked on 24 Nov 2026:

- **SEC current 8-K feed**: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=8-K&company=&dateb=&owner=include&start=0&count=100&output=atom`,
  newest first. Entry `title` `8-K - BridgeBio Pharma, Inc. (0001743881) (Filer)`; `link href`
  `https://www.sec.gov/Archives/edgar/data/1743881/000174388126000050/0001743881-26-000050-index.htm`;
  `summary type="html"`: `<b>Filed:</b> 2026-11-23 <b>AccNo:</b> 0001743881-26-000050 <b>Size:</b> 180 KB<br>Item
  8.01: Other Events<br>Item 9.01: …`; `category term="8-K"` (or `8-K/A`); `id`
  `urn:tag:sec.gov,2008:accession-number=0001743881-26-000050`. Item 1.05 filings are rare (four from 1 Oct to
  23 Nov 2026, e.g. Park Dental Partners, CIK 0002069604, accession 0001104659-26-115541, filed 2026-10-13).
  SEC requires a User-Agent naming a contact and allows 10 requests a second.
- **HHS OCR**: `breach_report.jsf` is now a landing page. The listing is
  `https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf` (cases under investigation, "Displaying 1 - 100 of
  692", newest submission first). Columns: Name of Covered Entity, State, Covered Entity Type, Individuals
  Affected, Breach Submission Date (`MM/DD/YYYY`), Type of Breach, Location of Breached Information, Business
  Associate Present, Web Description. The CSV/XML exports are JSF postbacks, which no pattern can make.
- **California AG**: `https://oag.ca.gov/privacy/databreach/list`, 50 rows a page, newest reported first.
  Columns: Organization Name (link to `https://oag.ca.gov/ecrime/databreach/reports/sb24-<digits>`), Date(s) of
  Breach (`MM/DD/YYYY`, several comma-separated, or `n/a`), Reported Date. The CSV export
  (`/privacy/databreach/list-export`) has no id or link column, so it can't key notices.
- **Washington AG**: Socrata dataset `sb4j-ca4h`, 1,710 rows (2015-08-11 to 2026-11-14).
  `https://data.wa.gov/resource/sb4j-ca4h.json` rows: `id` (digits), `name`, `datestart`, `dateend`, `dateaware`,
  `datesubmitted` (`2026-11-14T00:00:00.000`), `washingtoniansaffected` (digit string), `entitystate`,
  `databreachcause`, `cyberattacktype`, `industrytype`, `businesstype` and derived day/range/year fields.

## What to build

Touch only: new `packages/parsers/src/{notice-us,sec-edgar,hhs-ocr,ca-ag,wa-ag}.ts`, new tests in
`packages/parsers/test/`, one new `packages/patterns/test/page-breach-us.workers.test.ts`, new
`fixtures/{sec-edgar,hhs-ocr,ca-ag,wa-ag}/`, and the four source files
`packages/sources/src/sources/{sec-edgar,hhs-ocr,ca-ag,wa-ag}.ts`. No dependency changes; no change to
`types.ts`, patterns, `load.ts`, the registry, the linker, apps, E2B, migrations, `DATA_LICENSES.md` or other
sources. Never change a `licence`, `credit` or `cadence`.

### 1. Shared rules and `notice-us.ts`

- Each parser module exports a named parser and `export const parse`, returning
  `ParseResult<NoticeRecord> & { skipped: number }`. Worker-safe: no `node:` imports, `Buffer`, `fs`, `process`.
- Input: one item body (what the pattern yields) or an array of them. Anything else throws.
- `notice-us.ts` (helpers only; no `parse`) exports:
  - `usDate(s: unknown): string | undefined`: `MM/DD/YYYY` (1–2 digit month/day) → `YYYY-MM-DD`, real calendar
    dates only.
  - `isoDay(s: unknown): string | undefined`: the leading `YYYY-MM-DD` of a string if a real date.
  - `cleanName(s: unknown): string | undefined`: trim, collapse whitespace, strip control characters, ≤ 200 chars;
    empty → `undefined`.
  - `toCount(s: unknown): number | undefined`: a non-negative safe integer, or a string of digits with optional
    thousands commas; anything else (ranges, `n/a`, decimals, negatives, > 10^10) → `undefined`.
  - `noticeKey(...parts: string[]): string`: parts lower-cased, runs of non-`[a-z0-9]` → `-`, joined with `:`,
    ≤ 200 chars. Deterministic: the same row always gives the same `noticeId`.
- `count` is set only with a real unit. No count → omit `count` and use `countUnit: 'not_stated'`. Never add,
  merge or convert counts.
- `jurisdiction` is the regulator's place: `US` (SEC, HHS), `US-CA`, `US-WA`. `url` only when it is `https:` on
  the source's own host. A record without `rawName` or `noticeId` is skipped and counted.
- Never copy free text (HHS Web Description, 8-K item titles, breach cause narratives) into a record.

### 2. `sec-edgar.ts`: `parseSecEdgar(input): …`

Input: an Atom entry node as the feed pattern yields it. Keep it only if its form (`category.@_term`, else the
title prefix) is `8-K` or `8-K/A` **and** the summary text (tags stripped) lists `Item 1.05`
(`/\bItem 1\.05\b/`); other entries give no record and are not counted as skipped. From the entry:

| Field | Value |
| ----- | ----- |
| `noticeId` | accession number from the summary `AccNo`, else the `id` URN; must match `/^\d{10}-\d{2}-\d{6}$/` |
| `rawName` | title between `<form> - ` and ` (<cik>)` |
| `companyKey` | `cik:` + the 10-digit CIK from the title. The CIK in the link path (`/edgar/data/<cik>/`) must be the same number, else skip |
| `notified` | `Filed` date from the summary, else `isoDay(updated)` |
| `countUnit` | `not_stated` (8-Ks rarely give one) |
| `jurisdiction`, `url` | `US`; the link `href` if it starts `https://www.sec.gov/Archives/edgar/data/` |

An amendment (`8-K/A`) is its own notice (own accession). The filing header (`<accession>.hdr.sgml`) is not
read: the feed pattern makes one request per run, and the header adds only the period of report (for Item 1.05,
the date the company judged the incident material, not when it happened) and addresses, none of which
`NoticeRecord` holds. Entry keys outside `title, link, summary, updated, category, id` go to `unknownFields`.

### 3. `hhs-ocr.ts`: `parseHhsOcr(input): …`

Input: a row `{ name, state, entityType, individuals, submitted, breachType, location, associate }` from the
page pattern. `noticeId = noticeKey(submitted ISO, state, name)`; `rawName = cleanName(name)`;
`notified = usDate(submitted)` (required, else skip); `count = toCount(individuals)` with `countUnit:
'individuals'` (or `not_stated` without a count); `jurisdiction: 'US'`; `dataTypes: ['health']`; `url` the
listing URL. Row keys outside those eight go to `unknownFields`.

### 4. `ca-ag.ts`: `parseCaAg(input): …`

Input: a row `{ name, link, breachDates, reported }`. `link` must match
`^https://oag\.ca\.gov/ecrime/databreach/reports/(sb24-\d+)$`, else skip; group 1 is `noticeId`, the link is `url`.
`breachDates` split on commas, each `usDate`; valid dates give `occurredFrom` (earliest) and `occurredTo`
(latest); `n/a` or none → neither. `notified = usDate(reported)`. `countUnit: 'not_stated'` (the list gives no
count), `jurisdiction: 'US-CA'`.

### 5. `wa-ag.ts`: `parseWaAg(input): …`

Input: a dataset row object. Zod `looseObject` with `id` (digits) and `name` required, the rest optional
strings. `noticeId = id`; `occurredFrom = isoDay(datestart)`, `occurredTo = isoDay(dateend)`,
`discovered = isoDay(dateaware)`, `notified = isoDay(datesubmitted)`; `count = toCount(washingtoniansaffected)`
with `countUnit: 'state_residents'` (or `not_stated`); `jurisdiction: 'US-WA'`; `url`
`https://data.wa.gov/resource/sb4j-ca4h.json?id=<id>`. Known keys are the 25 dataset columns listed in
`fixtures/wa-ag/SOURCE.md`; others go to `unknownFields`. A range like `washingtoniansaffectedrange` is never
used as a count.

### 6. Source config

| Source | Change |
| ------ | ------ |
| `sec-edgar` | `parser: 'sec-edgar'`; `pull: { feed: { url: '<SEC feed URL above, count=100>', order: 'newest-first' } }` |
| `hhs-ocr` | `parser: 'hhs-ocr'`; **also** `pattern: 'page'`; `pull: { page: { url: '<HHS listing URL>', item, key: 'name', order: 'newest-first', fields } }` |
| `ca-ag` | `parser: 'ca-ag'`; **also** `pattern: 'page'`; `pull: { page: { url: 'https://oag.ca.gov/privacy/databreach/list', item, key: 'link', order: 'newest-first', fields } }` |
| `wa-ag` | `parser: 'wa-ag'`; **also** `pattern: 'fingerprint'`; `pull: { fingerprint: { url: 'https://data.wa.gov/resource/sb4j-ca4h.json?$order=datesubmitted%20DESC,id%20DESC&$limit=5000', format: 'json', key: 'id' } }` |

Selectors come from the live HTML: fetch both pages with `curl` from the sandbox, read the table markup and
write `item`/`fields` against it (HHS is a PrimeFaces table, likely `tbody[id$="reportResultTable_data"] > tr`
with `td:nth-child(n)` cells; California is a Drupal views table). Use attribute, child and `nth-child`
selectors only (what `HTMLRewriter` supports). The HHS `key` is the entity name because the listing has no id;
a repeat name only risks one missed row and is logged as a gap by the pattern. Add a one-line comment in each
changed file saying why the pattern changed (HHS export needs a postback; CA CSV has no id; WA Socrata needs
`$where`, which `since` can't send). The WA dataset is small (1,710 rows), so the fingerprint diff also catches
corrected counts.

Before committing, check each URL with `curl -sI` and a GET of the first bytes, sending
`ThreatIndex-test/0.1 (+https://github.com/Motiontic/threat-index)`, and save the status lines. If SEC answers
403 to that User-Agent, say so in the PR; don't guess.

### 7. Fixtures (each folder gets a `SOURCE.md`: URL, fetch date, licence, what was trimmed or hand-written)

- `fixtures/sec-edgar/current-8k.atom`: the real feed cut to 3 entries, plus two hand-written entries copying
  the real shape: Park Dental Partners (`8-K`, Items 1.05 and 9.01, facts above) and an `8-K/A` with Item 1.05
  whose link CIK differs from the title CIK. If SEC refused the sandbox, hand-write all five from the shape above.
- `fixtures/hhs-ocr/listing.html`: the real listing cut to 3 rows; `rows.json`: those rows as the page pattern
  yields them, plus hand-written rows with `individuals` `"n/a"`, a bad date `02/30/2026`, an unknown key.
- `fixtures/ca-ag/list.html`: the real page cut to 3 rows plus a hand-written row with `n/a` dates and one with
  `03/25/2026, 07/13/2026`; `rows.json`: the matching row objects plus one whose link is on another host.
- `fixtures/wa-ag/sb4j-ca4h.sample.json`: the real three newest rows (ids 26286, 26284, 26285) plus hand-written
  rows: no `washingtoniansaffected`, `"1,200"`, an unknown key, `id` `"abc"`.

### 8. Tests (Node: `packages/parsers/test/breach-us.test.ts`, `sources-breach-us.test.ts`; no network)

- Each fixture through its parser: exact records, `skipped` counts and `unknownFields`. SEC: only the 1.05
  entries give records; `companyKey` `cik:0002069604`; the CIK mismatch is skipped. HHS: `1351650` →
  `individuals`, `n/a` → `not_stated` with no `count`. CA: date ranges and `n/a`. WA: `16307` →
  `state_residents`, `"1,200"` → 1200, a missing count → `not_stated`.
- No record has a `count` with `countUnit: 'not_stated'`; the same input twice gives identical `noticeId`s.
- `notice-us` helpers: leap days, `13/01/2026`, thousands commas, `1e3`, `-5`, `12.5`.
- No record field contains Web Description text or item titles from the fixtures.
- `loadParser` resolves the four parsers. `sources-breach-us.test.ts`: `parser`, `pattern` and `pull` as in
  section 6; licences unchanged (`sec-edgar`, `hhs-ocr` `on`; `ca-ag`, `wa-ag` `ask`).
- `page-breach-us.workers.test.ts`: the page pattern's `fetch` on `fixtures/hhs-ocr/listing.html` and
  `fixtures/ca-ag/list.html` with the real configs yields exactly the rows in each `rows.json` (excluding the
  hand-written extras), so the selectors are proven against real markup.

## Not in scope

- Other state AGs (`state-ags` stays unwired). One source holds one pull URL, so each state (Maine, Oregon,
  Vermont, Montana, Iowa, Texas, Indiana…) needs its own source file and registry entry, and several publish
  only HTML detail pages or PDFs. Later, one state at a time.
- SEC filing headers, Item 8.01 voluntary cyber disclosures, a first load of Item 1.05 filings since Dec 2023
  (needs EDGAR full-text search or daily indexes in E2B), and catching up when more than 100 8-Ks arrive within
  one 3-hour cadence (the pattern logs the gap).
- HHS archive (closed cases) and history beyond the first 100 rows; CA history beyond page 1 (5,400 notices);
  CA detail pages and PDFs; WA's information-type dataset (`padd-mby7`) for `dataTypes`.
- Company matching, breach events, entity state as a field, pages and alerts.

## Acceptance criteria

1. `pnpm build` (lint, typecheck, `pnpm test`) and `pnpm test:workers` pass; save both outputs.
2. The four parser files export the functions named in sections 2–5 and `parse`; `notice-us.ts` exports the
   section 1 helpers.
3. The section 8 tests pass on fixtures only; no test makes a network request.
4. `git diff --stat main -- packages/sources/src` shows only the four source files; the diff changes only
   `parser`, `pull` and, for `hhs-ocr`, `ca-ag`, `wa-ag`, `pattern` (paste it in the PR).
5. `rg "from 'node:" packages/parsers/src` is empty; no new dependency; `pnpm-lock.yaml` unchanged.
6. Proof saved: the `curl` status lines for section 6, which fixtures are real or hand-written, and a table of
   fixture → records (count, units, noticeIds, skipped).
