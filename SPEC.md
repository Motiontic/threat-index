# breach-linking: match breach notices to companies and group them into breach events

## Why

Breach notices arrive one source at a time: an SEC 8-K Item 1.05 filing, then weeks later a California AG
notice, an HHS OCR entry and a Washington AG notice for the same incident. Today `link()` stores each notice on
its own with whatever `companyKey` the parser set, so nobody can watch a company, see one incident across
sources, or tell that "AT&T Inc." and "AT&T" are the same filer. This change adds company matching (SEC CIK,
then domain, then normalised name + state + a 30-day date window), writes `companies` rows with aliases,
groups notices into `breach_events`, and keeps every count with its unit: counts in different units, or from
different notices, are never added together. It is pure code in `@ti/linker`, tested in Node.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/core/src/types.ts` | `NoticeRecord { source, noticeId, rawName, companyKey?, occurredFrom?, occurredTo?, discovered?, notified?, count?, countUnit, jurisdiction?, dataTypes?, url? }`. `CountUnit` = `state_residents`, `individuals`, `accounts`, `not_stated`, `claim`. No CIK, domain or state field |
| `packages/linker/src/link.ts` | Step 1 keeps notices with `source`, `noticeId`, `rawName`, `countUnit`. Step 2 reads `breach_notices` once by `(source, notice_id)`. Step 5 writes `noticeRow()` and `noticeChange()` per notice, first record per key wins |
| `packages/linker/src/map/notice.ts` | `noticeRow(r, stored, now)`: full row; keeps stored `company_key` and `event_key`; null when only `modified` would change |
| `packages/linker/src/changes.ts` | `noticeChange(r, stored, at, newId)`: one `breach_notice` row for a notice not stored before that has a `companyKey`; `entity_key = companyKey`, `new = <source>:<notice_id>` |
| `packages/linker/src/tables.ts` | `ROW_ORDER`, `PRIMARY_KEYS`, `COLUMNS` cover `vulns`, `advisories`, `signals`, `techniques`, `breach_notices`, `incidents`, `changes`. No `companies` or `breach_events` |
| `packages/db/migrations/world/0001_init.sql` | `companies (key PK, name NOT NULL, cik, domain, ticker, sector, aliases)`; `breach_notices` with `company_key` indexed (`notices_by_company`) and `event_key`; `breach_events (key PK, company_key, first_seen NOT NULL, dates, counts_by_unit, notice_count NOT NULL DEFAULT 1, confidence, modified NOT NULL)` |
| `packages/db/src/table-info.ts` | Write rules come from the Drizzle schema: `companies` is `upsert` (no `modified`), `breach_events` and `breach_notices` are `newer`. `WRITE_ORDER` already lists `companies`, `breach_events`, `breach_notices` |
| `apps/collector/src/link-deps.ts` | `read(table, keys)` runs `SELECT * FROM <table> WHERE (<cols>) IN (VALUES …)` for whatever columns the keys carry (all keys in one call share them), chunked to D1's 100 bound parameters. Not limited to primary keys |
| `packages/linker/src/testing/fake-deps.ts`, `link.test.ts` | The fake reads by any column set. Test (l) asserts every table is read at most once; test (k) expects `entity_key: 'acme'` for a notice with `companyKey: 'acme'` |
| `packages/linker/src/schema.test.ts` | Parses `CREATE TABLE` in every migration and checks `COLUMNS`/`PRIMARY_KEYS` against it |

`link()` runs once per source run, so an SEC notice and the AG notices for the same incident almost never meet
in one batch. Matching must work against stored rows, which needs a lookup by normalised name.

## What to build

New code goes in `packages/linker/src/company.ts` and `packages/linker/src/breach.ts` (plus their tests).
`link.ts` changes only to call them for notices. Keep `LinkDeps`, `LinkResult`, `noticeRow` and `noticeChange`
signatures as they are.

### 1. Parser hints: the `companyKey` convention

`types.ts` gets no new field. A parser that knows an identifier passes it in `companyKey` as a hint:

- `cik:<1–10 digits>`: SEC filers (the 8-K parser sets this). Normalised to `cik:` + 10 digits, zero-padded.
- `domain:<host>`: sources keyed by site (HIBP). Lower-cased, a leading `www.` dropped; must match
  `^[a-z0-9-]+(\.[a-z0-9-]+)+$` and be at most 253 characters.

Any other value, or an invalid one, is ignored and the notice is matched by name. State this convention in a
doc comment on `hintKey()` so parser authors find it.

`jurisdiction` is read as ISO 3166-2 (`US-CA`) or ISO 3166-1 alpha-2 (`US`, `GB`), case-insensitive. Anything
else counts as unknown (`xx`).

### 2. `company.ts`

```ts
export type CompanyKey = string; // 'cik:0000123456' | 'domain:example.com' | 'name:<slug>:<juris>'
export function hintKey(raw: unknown): { key: CompanyKey; cik?: string; domain?: string } | null;
export function normaliseName(raw: string): string;          // '' when nothing is left
export function jurisdictionCode(raw: unknown): string;      // 'us-ca', 'us', 'gb' or 'xx'
export function nameKey(norm: string, juris: string): CompanyKey;
export interface Span { from: string; to: string }           // YYYY-MM-DD
export function incidentSpan(n: { occurredFrom?, occurredTo?, discovered?, notified? }): Span | null;
export function spansClose(a: Span, b: Span, days?: number): boolean; // default 30
export function companyRow(key: CompanyKey, rawNames: string[], stored: Row | undefined,
                           hint?: { cik?: string; domain?: string }): Row | null;
```

- `normaliseName`: NFKD and strip diacritics; lower-case; keep only the part before ` dba ` / ` d/b/a `;
  `&` → ` and `; punctuation to spaces; collapse spaces; drop a leading `the`; drop trailing legal suffixes
  repeatedly (`inc`, `incorporated`, `llc`, `l l c`, `llp`, `lp`, `ltd`, `limited`, `corp`, `corporation`, `co`,
  `company`, `plc`, `pllc`, `pc`, `pa`, `na`, `n a`, `sa`, `ag`, `gmbh`). Keep `group`, `holdings`, `health`
  and other words. If stripping leaves nothing, use the name before stripping suffixes.
- `nameKey`: `name:` + the normalised name with spaces as `-`, cut to 100 characters, + `:` + the
  jurisdiction code. Every key matches `^[a-z0-9:.@-]{1,200}$`; test that no input escapes it.
- `incidentSpan`: `from` = first ISO date of `occurredFrom`, `occurredTo`, `discovered`, `notified`; `to` = first
  of `occurredTo`, `occurredFrom`, `discovered`, `notified`; swapped if out of order; null with no date. It uses
  when the incident happened, not when letters went out, because AG letters follow an 8-K by months.
- `spansClose`: the spans overlap or the gap between them is at most `days` days (UTC dates).
- `companyRow`: `name` = the stored name, else the first raw name trimmed and cut to 200 characters;
  `cik`/`domain` from the hint, else stored; `ticker`, `sector` kept from stored; `aliases` = JSON list of
  normalised names, stored ones first then new, unique, at most 50. Null when nothing differs from stored.

### 3. Resolving a notice's company

Process notices in input order. A notice already stored keeps its stored `company_key` and `event_key`: no
re-matching here. For a new notice:

1. **CIK hint** → `cik:<10 digits>`, confidence 1.0.
2. **Domain hint** → `domain:<host>`, confidence 1.0.
3. **Name**: let `norm = normaliseName(rawName)`. Look at earlier notices with the same `name_key` (stored ones
   from the read below, plus earlier new notices in this batch) whose company key starts `cik:` or `domain:`
   and whose `incidentSpan` is close to this notice's (30 days). If any, take that company: prefer `cik:` over
   `domain:`, then the earliest such notice; confidence 0.8. Otherwise `nameKey(norm, jurisdictionCode(...))`,
   confidence 0.6. Without dates a notice never joins by name.

A notice whose `norm` is empty keeps `company_key` null, gets no event and emits no change (as today).

### 4. `breach.ts`: events

```ts
export interface LinkedNotice { idx: number; r: NoticeRecord; stored?: Row; companyKey: string | null;
  nameKey: string; confidence: number; eventKey: string | null }
export function assignEvents(linked: LinkedNotice[], prior: Row[]): void;   // fills eventKey
export function eventRow(key: string, notices: Row[], stored: Row | undefined, at: string): Row | null;
export function linkNotices(notices: Item<NoticeRecord>[], deps: LinkDeps, at: string,
  stored: Map<string, Row>): Promise<{ companies: Row[]; events: Row[]; notices: LinkedNotice[] }>;
```

- **Grouping**: a new notice joins an event of the same company when its span is close (30 days) to the span
  of any notice already in that event (stored or earlier in the batch). With several candidates it joins the
  one whose earliest notice is earliest; two existing events are never merged here. Otherwise it starts one
  with key `<companyKey>@<span.from>` (or `<companyKey>@<source>:<noticeId>` with no dates, cut so the key
  stays under 200 characters). If that key is already taken by an event that is not close, add `-2`, `-3`, ….
- **`eventRow`** is rebuilt from all of the event's notices (stored rows plus this batch's), never
  incrementally: `company_key`; `first_seen` = earliest `notified`, else the link date (`at` cut to a date);
  `dates` = JSON `{"from","to"}`, the union of the notices' spans; `counts_by_unit` = JSON
  `{ "<unit>": { "<jurisdiction or ->": <largest count seen> } }`, skipping null counts. No total is ever
  computed, and counts from different units or different jurisdictions stay separate; `notice_count` = number
  of notices; `confidence` = lowest notice confidence (stored notices count as 1.0 when their key is `cik:` or
  `domain:`, else 0.6); `modified` = `at`. Null when nothing but `modified` differs.

### 5. Schema: one migration, one column

Name lookup needs a stored normalised name. Add `packages/db/migrations/world/0002_notice_name_key.sql`:
`ALTER TABLE breach_notices ADD COLUMN name_key TEXT;` and `CREATE INDEX notices_by_name ON breach_notices
(name_key);`. `name_key` holds `normaliseName(rawName)`. Add the matching `nameKey: text('name_key')` and index
to `breach_notices` in `packages/db/src/schema/world.ts` (the writer validates columns against it); this is
the only `packages/db` edit. Extend the `schema.test.ts` parser to apply `ALTER TABLE … ADD COLUMN`.

In `tables.ts`: add `companies` and `breach_events` to `ROW_ORDER` before `breach_notices`, with
`PRIMARY_KEYS` (`key`) and `COLUMNS` in migration order; add `name_key` to `breach_notices` after `modified`.
Add their NOT NULL columns to `REQUIRED` in `testing/fake-deps.ts`.

### 6. `link.ts`

- Step 2 adds, after the existing `breach_notices` read: `breach_notices` by `{ name_key }` for every new
  notice's normalised name; then `companies` by `{ key }` for every resolved company key; then
  `breach_notices` by `{ company_key }` for those keys (prior notices for grouping); then `breach_events` by
  `{ key }` for the event keys those prior notices carry. Never call `read` with an empty key list. Update the
  `LinkDeps.read` doc comment: keys may be any indexed column set, and `breach_notices` is read at most three
  times (by key, by `name_key`, by `company_key`); every other table at most once. Update test (l) to match.
- Step 5 writes each notice through `noticeRow({ ...r, companyKey }, stored, at)`, then sets `name_key` and
  `event_key`; the row is emitted when any column other than `modified` differs from stored. `noticeChange` is
  called with the resolved `companyKey`, so every new notice with a key emits one `breach_notice` change and
  its `entity_key` is the resolved key. Emit `companies` and `breach_events` upserts with the first notice's
  `idx`. Update test (k): `companyKey: 'acme'` is not a hint, so `entity_key` is `name:acme:xx`.

### 7. Labelled test set

`packages/linker/src/testing/breach-set.ts` exports about 40 labelled notices, each
`{ record: NoticeRecord, expect: { companyKey: string; event: string; miss?: true } }`, modelled on public
incidents from 2023–2024 (e.g. UnitedHealth/Change Healthcare, AT&T, Live Nation/Ticketmaster, 23andMe, MGM
Resorts, Clorox, Caesars, Prudential). Notice details may be hand-written and approximate; say so in a header
comment. CIKs must be real: look each one up on SEC EDGAR (`https://www.sec.gov/cgi-bin/browse-edgar?company=…`
or `https://www.sec.gov/files/company_tickers.json`, with a descriptive `User-Agent`) and record in the PR
which were checked. If EDGAR is unreachable from the sandbox, say so and mark the CIKs unverified. Composition:

- about 10 SEC notices with a `cik:` hint, the filer name as `rawName`, a `discovered` date, `not_stated` count;
- about 22 state AG / HHS-style notices for those companies with name variants (case, punctuation, suffixes,
  `The`, `&`, `d/b/a`), in 2–4 jurisdictions, units `state_residents` and `individuals`, spans within 30 days;
  at most 1 labelled `miss: true` (a notice filed under a subsidiary name);
- negatives: a notice with the same normalised name as a CIK company but a span over 30 days away (must get a
  `name:` key and its own event); two unrelated small businesses with the same name in different states (two
  `name:` keys); a company with two incidents months apart (two events); a `domain:` hint notice.

`breach-set.test.ts` feeds the set through `link()` one source at a time, oldest first, applying rows to the
fake between calls (as the collector would), then asserts: (a) of notices labelled with a `cik:` key, at least
95% resolve to exactly that key, and print the rate; (b) no notice resolves to a `cik:` key other than its
label; (c) events match the labelled groups; (d) every `counts_by_unit` holds the source counts unchanged, by
unit and jurisdiction, with no sum.

### 8. Unit tests

`company.test.ts`: normalisation cases (suffixes, `&`, `dba`, diacritics, `The`, empty), hint parsing
(padding, bad CIK, bad domain, `www.`), key charset, spans (overlap, 30 vs 31 days, missing dates), aliases
capped and stored-first. `breach.test.ts`: grouping, key collision suffix, rebuild from stored notices, a stored
notice is never re-matched, rerunning the same batch emits no rows.

## Not in scope

- Re-keying: merging a `name:` company into a CIK company found later, or merging two events.
- Reading companies by domain or ticker, a CIK directory (SEC `company_tickers.json` as a lookup), sector or
  ticker enrichment, and subsidiary/parent mapping.
- Breach parsers and fixtures (other features), breach and company pages in the web app, alert delivery.
- Any change to `packages/core`, `apps/**`, or `packages/db` beyond the migration and schema column above.

## Acceptance criteria

1. `pnpm build` passes (lint, typecheck, Node tests); `pnpm test:workers` still passes.
2. `git diff --name-only main` lists only `packages/linker/src/**`,
   `packages/db/migrations/world/0002_notice_name_key.sql` and `packages/db/src/schema/world.ts`.
3. `breach-set.test.ts` passes with a CIK match rate of at least 95%, no wrong CIK and every count stored
   per unit; save its output, including the printed rate, as proof.
4. A test shows an event with `individuals`, `state_residents` from two states and a `not_stated` notice has
   all of them under separate keys in `counts_by_unit` and no total anywhere in the row.
5. Every new notice with a company emits exactly one `breach_notice` change whose `entity_key` is the
   resolved key; rerunning the same batch on the applied fake emits no rows at all.
6. `schema.test.ts` passes with `name_key`, `companies` and `breach_events` in `COLUMNS`.
7. With the `world` migrations applied locally (`wrangler d1 execute … --local --file` for 0001 then 0002),
   `PRAGMA table_info(breach_notices)` shows `name_key` and `PRAGMA index_list(breach_notices)` shows
   `notices_by_name`. Save the output.
8. The PR lists which CIKs in the test set were checked on EDGAR and how.

## Changes from the first build of this branch

The new `notices_by_name` index adds 1 to the loader's write cost for a `breach_notices` row, so three tests in
`apps/loader/test/consume.workers.test.ts` that expect 15 and 90015 now see 16 and 90016. That is correct. You
may update only those expected numbers in that file, with a comment naming the index. Re-run every acceptance
check.
