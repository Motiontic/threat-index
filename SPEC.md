# linker-core: turn parsed records into hot-set rows, aliases and change rows

## Why

Each collector step parses up to 40 records and has to decide, for every one: which flaw it belongs to, whether
that flaw is in the hot set that D1 holds, and what changed that a customer would act on. `link()` in
`packages/linker/src/link.ts` is where that happens, and today it is a stub. Other features are being built at
the same time against its types: the collector (`apps/collector/**`) calls `link()`, and the loader feature's
`writeRows()` (`packages/db/src/write.ts`) writes the returned rows, routing each one by table name. This change
fills in `link()`. It is pure code: no Workers APIs and no I/O except through `LinkDeps`.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/linker/src/link.ts` | `LinkDeps` (`read`, `lookupCold`, `now`, `newId`), `LinkResult` (`rows`, `docs`, `skipped`), `link()` throws `NotImplementedError` |
| `packages/linker/src/detect.ts` | `HOT_SINCE`, `EPSS_HOT`, `isHot()`, `epssBand()`, `ChangeKind` (the same six kinds as the `changes` CHECK list), `VulnState`, `detectChanges(before, after)`; tested |
| `packages/linker/package.json` | Depends only on `@ti/core`. Any new dependency, even a workspace one, changes `pnpm-lock.yaml` |
| `packages/core/src/types.ts` | `ParsedRecord` is a union of six shapes with no tag. `VulnRecord`, `SignalRecord` and `IncidentRecord` all have a `kind` field with different meanings |
| `packages/core/src/ids.ts` | `normaliseId()` (CVE upper-cased, GHSA body lower-cased, anything else trimmed), `isCve()`, `vulnKeyFor(id, aliases)` (first CVE, else own ID) |
| `packages/parsers/src/kev.ts` | The one real parser. Emits `SignalRecord`s `{ vulnKey, kind: 'exploited_wild', source: 'cisa-kev', ref: <CVE>, firstSeen: dateAdded, evidenceDate }`, plus a `ransomware` signal when CISA marks known ransomware use. No due date |
| `vulns` (ti_vulns) | 22 columns; `kind`, `title`, `modified` NOT NULL; `cwe` and `sources` are JSON text |
| `advisories` (ti_advisories) | PK `(source, source_id)`, `vuln_key` indexed, `status` CHECK; the alias map. `apps/api/src/lib/resolve-key.ts` finds an ID under the source that owns its prefix |
| `signals`, `changes` (ti_signals) | `signals` PK `(vuln_key, kind, source, ref)`, `kind` CHECK, no `modified`. `changes` `kind` CHECK, indexed on `at` |
| `techniques`, `breach_notices`, `incidents` (ti_world) | `techniques` has no `modified`. `breach_notices` and `incidents` need `modified NOT NULL`, which `NoticeRecord` and `IncidentRecord` don't carry |
| `packages/db/src/sql.ts`, `packages/core/src/r2-keys.ts` | `upsertNewerSql()` updates only when `excluded.modified > <table>.modified`. `vulnDocKey(key)` → `docs/vuln/<key>.json` |
| `apps/api/src/routes/watch.ts` | A user can watch any normalised ID, including one with no D1 row. Alerts match `changes.entity_key` to `watch.entry_key` |
| Missing data | No record type carries an EPSS score or a KEV due date. No D1 column holds affected or fixed versions |

## What to build

New files go in `packages/linker/src/`. Keep `LinkDeps`, `LinkResult`, `link` and every `detect.ts` export as is.

### 1. Telling records apart: `kinds.ts`

`types.ts` is not this feature's file, so add no tag. Add type guards keyed on fields only one shape requires,
checked in this order: `isNoticeRecord` (`noticeId`), `isIncidentRecord` (`incidentId`), `isAdvisoryRecord`
(`sourceId` and `status`), `isTechniqueRecord` (`framework` and `id`), `isVulnRecord` (`key` and an `aliases`
array), `isSignalRecord` (`vulnKey`, `ref` and `firstSeen`). Each is `(r: ParsedRecord) => r is <Type>`.
`recordKind(r): 'vuln' | 'advisory' | 'signal' | 'notice' | 'incident' | 'technique'` uses them and throws
`linker: unrecognised record` (no record content in the message) for anything else. The KEV parser stays as it is.

### 2. Tables and columns: `tables.ts`, `clean.ts`

- `tables.ts`: `type Row = Record<string, unknown>`; `type LinkTable`; `ROW_ORDER` = `vulns`, `advisories`,
  `signals`, `techniques`, `breach_notices`, `incidents`, `changes` (last, so a partly written batch never holds an
  alert without its data); `PRIMARY_KEYS` and `COLUMNS` per table, with real column names in migration order;
  `ALIAS_SOURCE = 'alias'`, `KEV_SOURCE = 'cisa-kev'`, `CVE_HOME_SOURCE = 'cve-list'`. Table and column names
  come only from here, never from record data.
- `clean.ts`: `vulnId(raw): string | null` (`normaliseId`, then `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, else
  null, so a key is safe in `docs/vuln/<key>.json`); `httpUrl(raw)` (keeps only `http:`/`https:` URLs, else
  null); `jsonList(values)` (sorted, unique, JSON); `readList(v)` (a stored JSON array, `[]` for anything else);
  `SUMMARY_MAX = 300`. CVSS outside 0–10 and counts that aren't non-negative integers are dropped.
- Every upsert row carries exactly `COLUMNS[table]`; a delete carries exactly `PRIMARY_KEYS[table]`. For
  columns a record doesn't set, the stored value is carried over, so the writer can use one column list per table.
- `modified`: on every row the linker writes (`vulns`, `advisories`, `breach_notices`, `incidents`) it is
  `deps.now().toISOString()`, meaning "when our row last changed". That always passes the writer's newer-wins
  check; source timestamps stay in the receipts. A row is emitted only when another column differs.

### 3. Reads

The linker passes `read(table, keys)` only primary-key objects with real column names and expects stored rows
with real column names back (the fake in tests matches rows whose columns equal every field of one key). Each
table is read at most once per call and never with an empty key list, in this order:

1. `advisories` (each advisory's `(source, source_id)`, and `(ALIAS_SOURCE, id)` for every non-CVE ID any vuln,
   advisory or signal record names), together with `techniques`, `breach_notices` and `incidents`;
2. `vulns`: every ID the records name, plus every `vuln_key` found in step 1's alias rows;
3. `signals`: each incoming signal's key under its resolved hub.

### 4. Hub keys and aliases: `hubs.ts`

`candidateIds(r)` returns a vuln, advisory or signal record's IDs through `vulnId`: own ID first (`key`,
`sourceId` or `vulnKey`), then `aliases` or the advisory's `vulnKey`. Unsafe aliases are dropped; if the own ID
is unsafe the record is dropped and counted in `skipped`. `resolveHubs(records, storedAliases, storedVulnKeys)`
returns one hub per record, by the first rule that applies:

1. the record names a CVE: the first CVE among its IDs, as `vulnKeyFor` picks it;
2. another record in this call names one of its IDs together with a CVE: that CVE (first such record wins);
3. a stored `(alias, id)` row exists for one of its IDs: its `vuln_key` (first ID in order that has one);
4. one of its IDs has a stored `vulns` row: the smallest such ID;
5. otherwise its own ID.

Aliases live in `advisories` under the reserved source `alias` (no source in the registry has that id), so any
ID resolves with one primary-key read. For every hot hub, each non-CVE ID its records name, other than the hub,
gets `{ source: 'alias', source_id: id, vuln_key: hub, status: 'active' }` when that row is missing or points
elsewhere. Two CVEs are never aliased or merged: a CVE in `aliases` that isn't the hub is ignored.

**Merging.** When a hot hub's records name a non-CVE ID `X` that has its own stored `vulns` row, `X` is merged
into the hub: the hub row takes `X`'s values for any column it lacks (`kev_added` keeps the earlier date, flags
are OR'ed, `sources` and `cwe` are unioned), the linker emits `{ table: 'vulns', op: 'delete', row: { key: X } }`
and points `(alias, X)` at the hub. CVE rows are never deleted. Known limit: `X`'s signals, watches and other
sources' advisory rows keep pointing at `X` until those records arrive again.

### 5. Folding a vulnerability: `draft.ts`, `map/vuln.ts`, `map/advisory.ts`, `map/signal.ts`

`draft.ts` exports `VulnDraft` (hub key, base row, row being built, `before: VulnState | null`, promoted or not,
source of the first new advisory with a fix, source behind each change kind, attached-record count),
`newDraft(key, base)` and `toVulnState(row)`. The base is the stored row, else the merged row of an alias key
(section 4), else the promotion summary (section 6), else empty. Records fold onto it in this order: vuln,
advisory, signal records, each in input order. One module per record kind:

- `map/vuln.ts` `applyVuln(d, r)`: `kind` is `cve` for a CVE hub, else the kind of the record whose own ID is the
  hub, else the base's, else `other`. The home record (source `cve-list` for a CVE hub; the record whose own ID is
  the hub otherwise) overwrites `title`, `summary` (cut to 300 chars) and `published`; other records only fill
  them when empty (a title equal to the key counts as empty). `cwe` is the union. CVSS belongs to the scorer that
  set it first (`cvss_source`, from `cvssSource ?? source`): a record from the same scorer updates `cvss`,
  `cvss_version`; another scorer's score is ignored, so two scorers never flip-flop.
- `map/advisory.ts` `advisoryRow(hub, r, stored)`, `aliasRow(id, hub, now)`: the advisory row keeps `status`,
  `published`, `url` (via `httpUrl`) and the stored `licence` (null on insert). An advisory whose
  `(source, source_id)` was not stored and that lists any `affected[].fixed` marks the draft's new fix.
- `map/signal.ts` `signalRow(hub, r)`, `applySignal(d, r)`: a signal row is emitted only when its key is not
  stored (the earliest `first_seen` wins within a call). A `cisa-kev` `exploited_wild` signal sets `kev_added`
  (earliest date); `ransomware` sets `ransomware = 1`; `public_exploit` sets `exploit_public = 1`. `poc`,
  `detection` and other sources' `exploited_wild` signals change no `vulns` column.
- Every attached record adds its source to `sources`. Each hot hub's `vulns` row has `hot = 1` and
  `doc_key = vulnDocKey(key)`.

### 6. Hot set and promotion

- A hub with a stored row, or a merged alias row, is hot. Otherwise it is hot when `isHot` says so on the folded
  row, or when it is promoted. Breach notices, incidents and techniques are always hot.
- **Promotion**: a hub with no stored or merged row that gets a `cisa-kev` `exploited_wild` or a `public_exploit`
  signal in this call. Only then is `deps.lookupCold(hub)` called, once, before folding; the summary becomes the
  base. The linker copies from it only `vulns` columns of the right primitive type, never `key`, `modified`, `hot`
  or `doc_key`. With a null summary the base is empty and `title` is the key until a vuln record arrives.
- A cold hub produces no rows; each of its records counts 1 in `skipped`.

### 7. World records: `map/notice.ts`, `map/incident.ts`, `map/technique.ts`

`noticeRow(r, stored, now)`, `incidentRow(r, stored, now)` and `techniqueRow(r, stored)` return the full row, or
null when nothing but `modified` would change. Notices keep the stored `event_key`, and the stored `company_key`
when the record has none; a `count` is never summed. Incidents keep the stored `gated` (0 on insert). List fields
are JSON lists and URLs go through `httpUrl`.

### 8. Change rows: `changes.ts`

`vulnChanges(d, at, newId)` and `noticeChange(r, stored, at, newId)` return `changes` rows
`{ id: newId(), entity_key, kind, old, new, at, source }`, with `at = deps.now().toISOString()` (one call per
`link()`) and `source` the record that caused it.

- Vulnerabilities use `detectChanges(before, after)`. `before` is the stored (or merged) row's state; on a
  promotion it is the summary's state, or `{ key }` when there is none, because a user can watch a cold ID. A
  first insert that is not a promotion writes no change rows: nobody watches a flaw we have never stored.
- `fix_released`: only for a hub whose base came from D1, when this call stores a new advisory with a fixed
  version; at most one per hub per call. D1 keeps no fixed versions, so a fix added to a stored advisory is missed.
- `epss_band` is never emitted: no record carries an EPSS score. `cvss_change` follows the scorer rule above.
- `breach_notice`: a notice whose `(source, notice_id)` was not stored and that has a `companyKey`;
  `entity_key = companyKey`, `new = <source>:<notice_id>`. Without a company key nobody can watch it.

### 9. `link()` and its result

`link()` classifies, reads (section 3), resolves hubs, promotes, folds, then builds rows. `rows` follow
`ROW_ORDER`, then input order within a table (deletes before upserts in `vulns`). `docs` is the sorted list of hot
hubs that got any row. `skipped` counts records of cold hubs and records dropped for an unsafe or empty ID.
Unchanged input produces no rows, and `link([])` returns `{ rows: [], docs: [], skipped: 0 }` without a read.

### 10. Tests (all in `pnpm test`, Node only)

Add `testing/fake-deps.ts`: in-memory tables keyed by `PRIMARY_KEYS`, a read log, `apply(rows)`, a fixed `now`,
`newId` giving `id-1`, `id-2`, …; it asserts every row's columns match section 2. Signals are shaped exactly as
`parseKev` emits them for `fixtures/cisa-kev/sample.json` (CVE-2025-3248, added 2025-05-05).

- `kinds.test.ts`: each of the six shapes is classified; a KEV signal is `signal`; an unknown object throws.
- `schema.test.ts`: reads `../../db/migrations/*/*.sql` with an eager `?raw` `import.meta.glob`, as
  `test/fixtures.ts` does, and checks that `COLUMNS` equals each `CREATE TABLE` column list, that every NOT NULL
  column without a default is always written, and that the change and signal kinds equal the CHECK lists.
- `hubs.test.ts`: the five rules; a GHSA with a CVE alias resolves to the CVE; with none, to itself; two CVEs
  never merge; unsafe IDs (`../x`, empty) are dropped.
- `link.test.ts`: (a) KEV on a stored hot CVE: a `signals` row, the `vulns` row with `kev_added`, `cisa-kev` in
  `sources` and `modified = now`, one `newly_exploited` change, `docs` = the CVE; (b) the same input after
  `apply()` gives no rows; (c) promotion of a cold CVE: `lookupCold` called once, row built from the summary,
  `ransomware = 1`, one `newly_exploited`; also with a null summary; (d) a 2019 vuln record alone, and a `poc` on
  a cold CVE, are skipped and call no `lookupCold`; (e) a new 2025 vuln record inserts with no change rows;
  (f) an advisory with a CVE writes its own row and an `alias` row; (g) a stored `GHSA-…` row merges into its CVE
  (delete plus alias), and a later signal on the GHSA lands on the CVE; (h) CVSS: same scorer ±1.0 gives
  `cvss_change`, another scorer is ignored, ±0.5 updates without a change; (i) two new advisories with fixes give
  one `fix_released`; (j) `public_exploit` sets `exploit_public` and one change; (k) notices with and without a
  company key, unchanged incidents and techniques; (l) each table read at most once, `advisories` before `vulns`
  before `signals`; (m) a `javascript:` URL is stored as null and a 400-char summary is cut to 300.

No Workers test: the linker uses no Workers API, and `schema.test.ts` checks rows against the migrations.

## Not in scope

- Company matching, `companies` rows, `breach_events` clustering and `event_key` (later breach work).
- EPSS scores and `epss_band` rows (the daily EPSS job), `kev_due`, CWE or incident links in `vuln_techniques`.
- Writing `docs/vuln/*.json`, cooling a hot flaw, moving signals or watches off a merged key, API `alias` lookups.
- Licence gates: the collector applies `canIngest` and the link-only rule before calling `link()`.
- Any file outside `packages/linker/`: migrations, dependencies, `@ti/core`, parsers and the other seams files.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process; `pnpm test:workers` still passes.
2. `git diff --stat main` lists only files under `packages/linker/`, and no `package.json` there changes.
3. `LinkDeps`, `LinkResult` and the `link` signature are unchanged from main; `detect.ts` keeps all its exports.
4. `map/` has one module per record kind, and `kinds.ts` tells all six apart with no change to `@ti/core/types`.
5. Every test in section 10 exists and passes, including `schema.test.ts` against the real migrations.
6. A test proves `read` is called at most once per table per `link()` call, in the order of section 3.
7. Re-running `link()` on the same input after its rows are applied returns no rows.
8. Proof saved: the `pnpm build` output, `pnpm vitest run packages/linker --reporter=verbose` output, and the
   `LinkResult` JSON for test (c), the KEV promotion of a cold CVE.
