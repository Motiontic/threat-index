# affected-data: package ranges for every advisory, as they arrive and for all loaded history

## Why

`POST /v1/packages/check` and the MCP tools built on it answer one question: is this package, at this version,
named by a known advisory? mcp-seams adds the two tables that hold the answer, `package_advisories` and
`affected`, and leaves them empty. This change fills them:

- the linker writes package rows for every advisory record that names packages, from any year, as records
  arrive;
- a new E2B job, `affected-backfill`, fills in the history already loaded, under its own daily write cap.

On the way it fixes what the parsers lose today: `last_affected`, full version lists, range types, "every
version" ranges on malicious packages, and the CVE List's registry entries. It also sets a `reviewed` flag, so
upgrade advice can use reviewed fixes only.

## Current state (main after mcp-seams; code checked at 00f7b56)

| Area | Today |
| ---- | ----- |
| `Affected` (`packages/core/src/types.ts:20-26`) | `{ ecosystem, name, introduced?, fixed?, range? }`. `AdvisoryRecord` (`:28-37`) has no summary, severity or review flag |
| OSV parser (`packages/parsers/src/osv.ts`) | One parser for `osv`, `github-advisory-db`, `openssf-malicious-packages`, `debian` and `ubuntu` (profiles in `osv-*.ts`). `affectedOf` (169-200) keeps SEMVER and ECOSYSTEM ranges (187) and drops the range type. `pairsOf` (136-167) turns `last_affected` into the display text `range: '<= x'` (159). A `versions` list is used only when no pair is "useful" (191-197), and becomes display text of at most 20 versions plus "(+N more)" (`versionsEntry` 130-134, `MAX_VERSIONS` 44). A bare `introduced: "0"` range is dropped when a list exists, so fixture `MAL-2026-12884` comes out as `range: "35.3.8"`, not "every version". Summary is kept only on the `VulnRecord` made when there is no CVE (288-307). Severity, GHSA's `github_reviewed` and Go's `review_status` are not kept. At most 200 entries (`MAX_AFFECTED`, 17) |
| CVE List parser (`cve-json5.ts`) | `cna.affected` is a known field (104) that is never read. A published CVE gives a `VulnRecord` only. An `AdvisoryRecord` exists only for REJECTED (261-268). `collectionURL` and `packageName` never leave the parser |
| NVD parser (`nvd.ts`) | `configurations` is known but not mapped (34). Only rejected CVEs give an `AdvisoryRecord` (109-118), with no `affected` |
| CSAF parser (`csaf.ts`) | `affectedOf` (184-205) emits vendor products: `ecosystem` is the vendor name (for example "Red Hat"), `fixed` is the product version. Red Hat purls are `pkg:rpm/redhat/...` builds (fixture `red-hat/cve-2023-38545.json`), not registry packages |
| CERT/CC parser (`cert-cc.ts`) | IDs, dates, URL and CVEs only (`build`, 118-135). No `affected` |
| Linker (`packages/linker/src/link.ts`) | Writes `advisories` only for hot hubs (cold hubs stop at 303-306). The first new advisory with a `fixed` value sets `fixSource` (279), which drives `fix_released` alerts (`changes.ts:18`, `detect.ts:69`). `LinkDeps.read` takes the columns of one index per table (39-47). `ROW_ORDER` and `COLUMNS` live in `tables.ts:7-104`; `schema.test.ts` checks them against the migrations |
| Linker callers | The collector Worker writes one step's rows in one `writeRows` call at steady priority (`apps/collector/src/step.ts:266-276`). A step holds at most 40 items (`packages/patterns/src/types.ts:13`). Its `readRows` takes any key columns (`apps/collector/src/link-deps.ts:26-60`). Sandbox loads read only `vulns`, `advisories` and `signals`, each paged whole (`e2b/jobs/src/jobs/first-load.ts:34, 47-116`). Any other table reads as empty (93) |
| Write planner (`packages/db/src/plan.ts`) | One call takes at most 500 rows, or throws `WriteLimitError` (134-135). Cost is rows × (1 + secondary indexes) (192), for deletes too: 3 per `affected` row, 2 per `package_advisories` row. Upserts run before deletes within a table (158). A delete carries key columns only (113-117) |
| Write rules (`packages/db/src/table-info.ts`) | A table with a `modified` column gets "newer wins" (69-76), so `package_advisories` will. A table without one needs an `OTHER_RULES` entry (31-40), or its rule is `none` and every write is refused. `WRITE_ORDER` (98-113) does not list the new tables. mcp-seams says they get "the default upsert rule" (see Coordination 1) |
| Budget (`packages/core/src/budget.ts`) | One daily meter for all writes. Steady writes are counted and never blocked (41-48). First-load writes stop when the meter reaches 1,000,000 (50-55), so steady writes shrink that day's first-load room |
| Inbox (`apps/loader/src/inbox-tables.ts:5-16`, `chunk.ts:107`) | Ten tables. A chunk naming `affected` or `package_advisories` is refused as corrupt |
| Job priority (`apps/api/src/routes/internal-jobs.ts:447`) | `first-load` jobs load at first-load priority; every other kind at steady |
| Job kinds | Source kinds `first-load`, `epss-diff`, `big-file`; global kinds `nightly-fold`, `search-index` (`apps/api/src/lib/e2b.ts:31-46`). The global start schema reads `GLOBAL_JOB_KINDS` (`internal-jobs.ts:86-99`). Sandbox side: `e2b/jobs/src/types.ts:4-13`, `run.ts:15-24`. A job lives at most 50 min (`JOB_TIMEOUT_MS`) and writes at most 5,000 chunks (`MAX_CHUNKS`) |
| Sandbox storage (`apps/api/src/lib/presign.ts:37-53`) | Every job may read `raw/`, `lake/`, `lookup/` and its own `jobs/<id>/`. It may write its own `jobs/<id>/` and `inbox/<id>/`, plus `lake/records/<source>/` for `first-load` only. No prefix lets one run leave state for the next. `big-file` may not write `lake/records/`, yet `runLoad` writes a lake part per batch in both modes (`first-load.ts:270-297`); see Coordination 7 |
| Sandbox network (`e2b.ts:118-123`) | `Sandbox.create(template, { apiKey, timeoutMs, metadata, requestTimeoutMs })`: no network limit. The SDK in use (e2b 2.64.0) has `network: { allowOut, denyOut }`. `allowOut` takes hostnames; `denyOut: ({ allTraffic }) => [allTraffic]` blocks everything else. When `allowOut` names a host, the SDK also allows its DNS servers (8.8.8.8 by default) |
| History in R2 | `lake/records/<source>/<yyyy>/part-<jobId>…`: parsed records as JSON, from sandbox loads, written by the parsers of the day. `raw/<source>/<yyyy>/<mm>/<dd>/<runId>-<step>.ndjson.gz`: the collector's receipts, written before parsing (`step.ts:190-201`), with each item's raw body (`apps/collector/src/receipt.ts:41-45`); folded nightly into `lake/raw/`. Sandbox downloads (first-load archives and change lists, big-file) are not kept raw |
| Change-list first loads (`e2b/jobs/src/lib/changelist.ts:10, 72-81`) | A first load keeps the newest 10,000 documents. So `osv`, `debian` and `ubuntu` history is their newest 10,000 records at first load, plus steady updates since |
| Git heavy jobs (`packages/patterns/src/git.ts:126-169`) | A commit with 300 or more changed files, a missing base or a diverged branch hands the whole repository archive to a `big-file` or `first-load` job |
| From mcp-seams | Migration advisories `0002`: `package_advisories` (key `source, source_id`; index by `vuln_key`) and `affected` (key `ecosystem, name, source, source_id, range_no`; indexes by record and by `vuln_key`). `@ti/core/packages`: `ECOSYSTEMS` (16 names, including `Debian`, `Ubuntu`, `Red Hat`), `canonicalEcosystem`, `normaliseName`. `@ti/core/versions`: `inRange` returns `'unsupported'` for ranges until comparers land; `EXACT` rows match by string |

### What the backfill can read

The lake copies are not enough. They were written by the old parsers, so they lack:

- `last_affected` as data (only display text) and the range type;
- version lists longer than 20, and every list as data;
- "every version" on malicious packages;
- summary and severity on advisories that have a CVE, and every review flag;
- every CVE List registry entry.

`raw/` is not enough either. It holds only what the collector Worker fetched. The bulk of each source arrived
through first-load sandboxes, which keep no raw copy.

So the backfill works in two steps:

1. **Refresh the lake.** After this change is deployed, re-run `first-load` for each package source. Its new
   parsers write full lake copies. These sandboxes keep their normal network access, because they download.
2. **Fill from R2 only.** `affected-backfill` reads `lake/records/` plus `raw/` receipts, re-parsing each
   receipt item with today's parser. It keeps the latest copy of each record and writes package rows. This
   sandbox reaches only the MTI API.

Two other options were rejected:

- **Let the refresh first-loads write the package rows.** They load at first-load priority, so they share the
  1,000,000 cap and are deferred for days. They have no dry run, no own cap and no resume point. A row that
  lands days late can also overwrite a newer one.
- **Let the backfill download the sources itself.** Its sandbox may reach only the MTI API.

Reading `raw/` as well matters. The collector writes its receipt before it links. So every version the steady
path has written is in R2, and the backfill never writes an older copy over it, except in the short race
described under "Known limits".

## What to build

Files: `packages/core/src/types.ts`, `packages/parsers/src/osv.ts`, `packages/parsers/src/cve-json5.ts`,
`packages/linker/src/affected.ts` (new), `packages/linker/src/link.ts`, `apps/loader/src/inbox-tables.ts`,
`e2b/jobs/src/jobs/affected-backfill.ts` (new), `e2b/jobs/src/jobs/first-load.ts`, `e2b/jobs/src/lib/inbox.ts`,
`e2b/jobs/src/run.ts`, `e2b/jobs/src/types.ts`, the kind lists in `apps/api/src/lib/e2b.ts`, plus tests and one
new fixture. No migrations, Wrangler configs, `apps/mcp`, `packages/core/src/packages.ts`, `versions/` or API
routes. `nvd.ts`, `csaf.ts` and `cert-cc.ts` get tests only (section 4). `internal-jobs.ts` needs no change,
because its global start schema already reads `GLOBAL_JOB_KINDS`.

### 1. Record shape (`packages/core/src/types.ts`)

```ts
export type RangeType = 'SEMVER' | 'ECOSYSTEM' | 'EXACT';

export interface Affected {
  ecosystem: string; // as the source wrote it: PyPI, npm, Debian:12, or a vendor name
  name: string;
  introduced?: string;
  fixed?: string;
  range?: string; // display text, meaning unchanged
  /**
   * Set only for registry packages: OSV entries, and CVE List entries with a known collectionURL and a
   * packageName. Unset means a vendor product. It is shown, but never package-matched.
   */
  rangeType?: RangeType;
  lastAffected?: string;
  /** EXACT only: every listed version, at most 1,000. */
  versions?: string[];
}

export interface AdvisoryRecord {
  // ...existing fields
  summary?: string;   // plain text, whitespace collapsed, at most 300 characters
  severity?: string;  // the source's label ("HIGH", "MODERATE") or a CVSS base score ("9.8")
  reviewed?: boolean; // see section 2
}
```

Every new field is optional. Old lake copies, `packages/core/src/api.ts`, the web guards and deep-query keep
working. Package-aware parsers (OSV and CVE List) set `reviewed`, true or false, on every `AdvisoryRecord`
they emit. The backfill uses its presence to tell a new copy from an old one.

### 2. OSV parser (`packages/parsers/src/osv.ts`)

The profile files `osv-*.ts` do not change.

**Per affected entry** (package name and ecosystem are kept as written; the linker canonicalises them):

- Each SEMVER or ECOSYSTEM range gives one entry per pair, with `rangeType` set to the range's type.
- The events walk:
  - `introduced` opens a pair (`introduced` is left unset when it is "0");
  - `fixed` closes it;
  - `last_affected` closes it into `lastAffected`, and keeps the display text `'<= x'`;
  - `limit` is ignored;
  - a pair still open at the end stays open.
- A bare `introduced: "0"` pair is kept. It means every version.
- GIT ranges are skipped, as now.
- A `versions` list gives one EXACT entry, `{ rangeType: 'EXACT', versions, range: <today's display text> }`,
  only when the entry has no SEMVER or ECOSYSTEM pair. OSV counts a version as affected when it is in any range
  or in the list ([schema, "Evaluation"](https://ossf.github.io/osv-schema/#evaluation)), so next to a range the
  list adds nothing. MAL records (an `introduced: "0"` range plus the versions seen) therefore mean every
  version.
- A list of more than 1,000 versions keeps only its display entry, with no `rangeType`.
- The dedupe key gains `rangeType`, `lastAffected` and `versions`. `MAX_AFFECTED` stays 200.

**Per record**, on every `AdvisoryRecord`:

- `summary`: the same text the `VulnRecord` gets today. That is `summary`, or else the first 2,000 characters
  of `details`, with whitespace collapsed and cut to 300 characters.
- `severity`:
  - `database_specific.severity` when it is one word (GHSA: LOW, MODERATE, HIGH, CRITICAL);
  - else the score of a `severity[]` entry of type `Ubuntu` (for example "medium");
  - upper-cased, at most 16 characters;
  - else unset. CVSS vectors are not turned into scores here.
- `reviewed`: from one exported function, so the rule lives in one place:

```ts
/** True only when fix versions come from the ecosystem's own vulnerability database or a reviewed advisory. */
export function reviewedFix(source: string, id: string, databaseSpecific: Record<string, unknown>): boolean;
```

| Source | `reviewed` is true when |
| ------ | ----------------------- |
| `github-advisory-db` | `database_specific.github_reviewed === true` (fixtures `GHSA-9x82-4j54-863h`, `GHSA-no-cve`) |
| `osv` | the id starts with `PYSEC-` (PyPA advisory database) or `RUSTSEC-` (RustSec advisory database); or it starts with `GO-` and `database_specific.review_status === 'REVIEWED'` (Go vulnerability database, which also holds `UNREVIEWED` reports; fixture `GO-2026-5006`) |
| `debian`, `ubuntu` | always: the profiles keep only `DEBIAN-CVE-` and `UBUNTU-CVE-` ids, whose fixes come from the distribution's own security tracker |
| `openssf-malicious-packages`, `MAL-` ids in `osv`, `cve-list`, every other id | never |

Other OSV databases (for example `HSEC-`, `RSEC-`, `JLSEC-`) stay false until someone checks how each one
reviews fixes.

**Display change:** a malicious package now shows one "every version" line instead of the versions seen.

### 3. CVE List parser (`packages/parsers/src/cve-json5.ts`)

For a PUBLISHED record, read `containers.cna.affected`. An entry counts only when it has a `packageName` and an
`https:` `collectionURL` whose host is in this table. Hosts come from the
[CVE JSON 5 schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json)'s
`collectionURL` examples, plus the forms CNAs commonly write.

| `collectionURL` host | Ecosystem |
| -------------------- | --------- |
| `pypi.org`, `pypi.python.org` | PyPI |
| `registry.npmjs.org`, `www.npmjs.com`, `npmjs.com` | npm |
| `crates.io` | crates.io |
| `pkg.go.dev`, `golang.org`, `proxy.golang.org` | Go |
| `repo.maven.apache.org`, `repo1.maven.org`, `central.sonatype.com` | Maven |
| `rubygems.org` | RubyGems |
| `nuget.org`, `www.nuget.org` | NuGet |
| `packagist.org` | Packagist |
| `hex.pm`, `repo.hex.pm` | Hex |
| `pub.dev` | Pub |

Every other host (`github.com`, `packages.debian.org`, `wordpress.org` and so on) is vendor or product data. It
is not emitted at all.

The `versions[]` items of a counted entry map like this. "Lower" is the item's `version`. It becomes "0" when
it is `0`, `*`, `unspecified` or `n/a` and the item has an upper bound.

| Item | Entry |
| ---- | ----- |
| `status: affected`, `lessThan` L (not `*`) | ECOSYSTEM, introduced = lower, fixed = L |
| `status: affected`, `lessThanOrEqual` E | ECOSYSTEM, introduced = lower, lastAffected = E |
| `status: affected`, `lessThan: "*"` | ECOSYSTEM, introduced = lower, open |
| `status: affected`, no bound | added to one EXACT entry per package |
| `defaultStatus: affected`, with exactly one `status: unaffected` item (version V, `lessThan: "*"`) and no affected item | ECOSYSTEM, introduced "0", fixed = V |
| `versionType: git`, any item with `changes`, any other shape | skipped |

Unlike OSV lists, CVE exact versions are statements of their own. So the EXACT entry is kept next to ranges.

When at least one entry maps, the parser also emits:

```ts
{ source: 'cve-list', sourceId: id, vulnKey: id, status: 'active', published, modified,
  url: `https://www.cve.org/CVERecord?id=${id}`, summary, // the CNA description, as the VulnRecord has it
  severity: score ? String(score.cvss) : undefined, reviewed: false, affected }
```

When nothing maps, the output is exactly today's. ADP containers' `affected` is not read. The rejected path does
not change.

### 4. NVD, CSAF and CERT/CC: no code change

None of them sets `rangeType`, so none of their entries reaches the package tables. That matters most for CSAF.
Its vendor name "Red Hat" would otherwise canonicalise to the `Red Hat` ecosystem, with RPM build versions as
fixes. NVD CPE configurations and CERT/CC `sysaffected` stay unmapped. Tests pin all three (section "Tests").

### 5. Linker: `packages/linker/src/affected.ts` (new)

Pure code. It imports `@ti/core/packages` (from mcp-seams), `@ti/core/inbox`, `@ti/core/types` and `./clean`.

```ts
export const AFFECTED_COLUMNS = ['ecosystem', 'name', 'source', 'source_id', 'range_no', 'vuln_key',
  'range_type', 'introduced', 'fixed', 'last_affected', 'versions'] as const;
export const AFFECTED_KEY = ['ecosystem', 'name', 'source', 'source_id', 'range_no'] as const;
export const PACKAGE_ADVISORY_COLUMNS = ['source', 'source_id', 'vuln_key', 'status', 'summary', 'severity',
  'reviewed', 'url', 'published', 'modified'] as const;
/** Meter units per row: 1 + secondary indexes in migration 0002 (the loader test checks this against planWrites). */
export const ROW_COST = { affected: 3, package_advisories: 2 } as const;
export const MAX_EXACT_VERSIONS = 1000;

export type SkipReason = 'no_range_type' | 'git_range' | 'unknown_ecosystem' | 'bad_name' | 'bad_version';

export interface PackagePlan {
  /** Distinct (ecosystem, name) pairs that survived the checks. */
  names: number;
  /** The package_advisories row. Built for every record; written only as packageWrites decides. */
  advisory: Row;
  /** Full affected rows with range_no set. Empty for withdrawn and rejected records. */
  ranges: Row[];
  skipped: Partial<Record<SkipReason, number>>;
}

/** Same record, same rows: the linker and the backfill write identical rows. */
export function affectedRows(r: AdvisoryRecord): PackagePlan;

export interface StoredPackageRows {
  advisory?: Row; // the stored package_advisories row, if any
  ranges: Row[];  // the record's stored affected rows (key columns are enough)
}

/**
 * The inbox rows for one record, in this order: affected upserts, affected deletes, then the
 * package_advisories upsert.
 * - Nothing when the stored advisory row's `modified` is the same or newer.
 * - Nothing when no package survived and there is no stored row.
 * - Otherwise: the plan's ranges, a delete for each stored range key the plan no longer has, and the advisory row.
 */
export function packageWrites(r: AdvisoryRecord, plan: PackagePlan, stored: StoredPackageRows): InboxRow[];

export function packageCost(rows: readonly InboxRow[]): number;
```

**`affected` row** for each entry with a `rangeType` (others count as `no_range_type`):

- `ecosystem`: the text before the first `:` goes through `canonicalEcosystem`.
  - Unknown (Hackage, CRAN, OSS-Fuzz and others) counts as `unknown_ecosystem`.
  - For `Debian`, `Ubuntu` and `Alpine`, the release suffix is kept as OSV writes it, for example
    `Debian:12` or `Ubuntu:Pro:14.04:LTS`. It must match `^[A-Za-z0-9._:-]{1,64}$`. Fix versions differ per
    release, and dropping the release would let an unfixed bullseye row match a bookworm user.
  - Any other ecosystem with a suffix counts as `unknown_ecosystem`.
- `name`: `normaliseName(canonical base, name)`; null counts as `bad_name`.
- `source`, `source_id`: as the `advisories` row has them (`vulnId(r.sourceId)`). A record whose id fails
  `vulnId` gives no rows.
- `vuln_key`: `vulnId(r.vulnKey ?? r.sourceId)`. This is the record's own CVE or id, not the linker's alias hub,
  so the backfill (which has no hub map) writes the same value.
- `range_type`, `introduced` (default `'0'`), `fixed`, `last_affected`. `versions` is `JSON.stringify(list)` for
  EXACT rows, otherwise null.
- Every version string must match `^[\x21-\x7e]{1,128}$` (printable ASCII, no spaces), or that row counts as
  `bad_version`.
- Identical rows of one package are written once.
- `range_no` numbers the rows of each (ecosystem, name) from 0, in record order. Numbering per package, not per
  record, keeps keys stable when a source reorders its packages. The key stays unique.

**`package_advisories` row:**

- `source`, `source_id`, `vuln_key` as above;
- `status`;
- `summary` (`cutSummary`, at most 300);
- `severity` (at most 16 characters, else null);
- `reviewed` (1 or 0);
- `url` (`httpUrl`), `published` (`isoDate`);
- `modified` = `r.modified`. This is the source's own time, not the linker's clock, so "newer wins" compares
  source versions.

A withdrawn or rejected record keeps its advisory row with that status, and has no ranges.

### 6. Linker call site (`packages/linker/src/link.ts`)

- **Collect.** After step 1, take every advisory item that passed the checks. That is hot and cold, any year.
  Keep one record per (`source`, `sourceId`): the highest `modified`, the last one on a tie. Run `affectedRows`
  on it.
- **Read.** Only for records with `names > 0` or a status other than `active`. Run at most two more reads per
  `link()`, both skipped when there are no keys:
  - `read('package_advisories', [{ source, source_id }])`
  - `read('affected', [{ source, source_id }])`, by the table's record index.
- **Write.** Call `packageWrites` per record. Append the rows just before the `changes` rows. Keep each record's
  rows next to each other.
- **No new alerts from the CVE List.** `fixSource` (line 279) ignores `cve-list` advisories, because they never
  carried fixes before. A hot CVE whose CVE List record is re-read must not raise `fix_released`. Their
  `advisories` row is written like any other advisory's.
- **Docs.**
  - `LinkDeps.read` allows `affected` keyed by `source, source_id`.
  - `LinkResult.rows` says package rows are included for every advisory record, hot or cold.
  - `skipped` keeps its meaning.

In a sandbox both reads return `[]` (`first-load.ts:93`). Sandbox runs therefore write upserts with no deletes
and no "newer wins" check (Coordination 6).

### 7. Loader (`apps/loader/src/inbox-tables.ts`)

Add `affected` and `package_advisories` to `INBOX_TABLES`. Note in the comment that the linker and the backfill
write them. Deletes of `affected` rows arrive with key columns only, which `planWrites` already requires.

### 8. Sandbox loads (`e2b/jobs/src/jobs/first-load.ts`)

- **First-load mode.** Drop `affected` and `package_advisories` rows before `writeInbox`, and log the count.
  They would load at first-load priority, days late and outside the backfill's cap. The backfill writes them
  from the lake parts this run leaves (section 9, "re-open").
- **Update mode (`big-file`).** Keep them, so new data keeps flowing. There are two exceptions; in both, drop
  them and log `package rows left to the backfill`:
  - the input shape is `archive`: a whole-repository re-read, where changed and unchanged records look alike;
  - their cost passes `UPDATE_PACKAGE_WRITE_CAP = 200_000` meter units.
- Reads do not change.

### 9. The backfill job (`e2b/jobs/src/jobs/affected-backfill.ts`)

**Wiring:**

- `JOB_KINDS` in `e2b/jobs/src/types.ts` and `JOBS` in `run.ts` gain `affected-backfill`.
- In `apps/api/src/lib/e2b.ts`, `GLOBAL_JOB_KINDS` and `ENABLED_JOB_KINDS` gain it, and the
  `GLOBAL_JOB_KINDS` comment says that only `nightly-fold` and `search-index` run on the collector's crons.
- `e2b/jobs/src/lib/inbox.ts` gains `writeInboxChunks(api, jobId, chunks: InboxRow[][], now)`. It writes
  chunks that are already packed (1–500 rows each), then the manifest. `writeInbox` becomes a wrapper that slices
  at 500.

**Start and limits:**

- An operator starts the job with `POST /internal/jobs { kind: 'affected-backfill', reason }`.
- The start route allows one active job of a kind, so runs never overlap.
- It loads at steady priority (`internal-jobs.ts:447`): never deferred, and never taking first-load priority.

**Sources:** every registry source with `canIngest(licence)` whose parser is in
`PACKAGE_PARSERS = ['osv-ghsa', 'osv', 'osv-malicious', 'cve-json5', 'osv-debian', 'osv-ubuntu']`, in that order
(reviewed data first). Today these are `github-advisory-db`, `osv`, `openssf-malicious-packages`, `cve-list`,
`debian` and `ubuntu`.

**State:** `lake/state/affected-backfill/state.json` (needs Coordination 3). `lake/` is already readable by
every job.

```ts
interface BackfillState {
  v: 1;
  countedBy: string | null;   // job id of the dry run; null = the next run is a dry run
  day: string;                // UTC day that writesToday belongs to
  writesToday: number;        // meter units this job emitted on that day
  sources: Record<string, {
    after: string | null;     // resume point: the last sourceId written, in code-unit order
    done: boolean;
    completedAt: string | null;
    records: number; rows: number; writes: number;
  }>;
}
```

A missing state means a fresh start. A malformed one fails the run. The job never guesses. Each field is checked
by hand, because the sandbox package has no zod.

**Constants:**

- `DAILY_WRITE_CAP = 600_000` meter units. With the 1,000,000 first-load cap, that is the 1,600,000-a-day figure
  in `budget.ts`.
- `RUN_BUDGET_MS = 40 min`: no new record is started after this. The job limit is 50 minutes.
- `MAX_SOURCE_BYTES = 8 GiB` and `MAX_COPIES = 2_000_000` per source: over either, the run fails before reading.

**Each run:**

1. **Egress check.** Fetch `https://1.1.1.1/` with a 5-second timeout (through `JobDeps.fetch`). If it
   answers, fail with `affected-backfill: egress not restricted`. The job runs only in a sandbox that reaches
   the MTI API alone.
2. **Read the state.** Start the clock. A source is picked when:
   - it is not done; or
   - it is done, but has a lake part whose job id is newer than `completedAt`. It is then **re-opened**:
     `after = null`, and only records whose latest copy comes from such a part are written.
3. **Load each picked source's history.**
   1. List `lake/records/<source>/` and read each part (`readLakePart`; Parquet goes through DuckDB). Keep the
      `AdvisoryRecord`s that carry `reviewed`. Count the rest as `oldFormat`.
   2. List `raw/<source>/`. Gunzip each receipt and take its `item` lines. Run `parser.parse(body)` with the
      source's parser (`loadParser`) and keep the `AdvisoryRecord`s. Count parse failures; they are not fatal.
   3. Keep the latest copy per (`source`, normalised `sourceId`): the highest `modified`. On a tie, keep the
      later origin (receipt `runId` or lake `job_id`; both are time-ordered ULIDs).
4. **Dry run** (when `countedBy` is null):
   - run `affectedRows` on every latest copy and count;
   - write `jobs/<id>/counts.json` (below) and an empty manifest;
   - set `countedBy` and log the totals.
   - No package rows are written.
5. **Write run:**
   - `remaining = DAILY_WRITE_CAP - writesToday`. `writesToday` resets when `day` changes.
   - Walk the latest copies in `sourceId` order, after `after`. For each: `plan = affectedRows(r)`, then
     `rows = packageWrites(r, plan, { ranges: [] })`.
   - Stop before a record would pass `remaining` or the time budget.
   - Pack whole records into chunks of at most 500 rows. A record's package rows never span two chunks. A record
     has at most 201 rows.
   - At the end of a walk, mark the source `done` and set `completedAt`. Then go on to the next source while
     the cap and the clock allow.
6. **Write in this order:** the chunks, then the manifest, then the state. Log per source: `from`, `to`, records,
   rows, units. Log no other record data.

```ts
interface BackfillCounts {
  jobId: string; createdAt: string; dailyWriteCap: number;
  sources: Record<string, {
    copies: number; latest: number; oldFormat: number; parseFailures: number;
    packageRecords: number; rows: number; writes: number;
    byEcosystem: Record<string, { rows: number; writes: number }>; // base name, before any ':'
    byRangeType: Record<RangeType, number>;
    skipped: Partial<Record<SkipReason, number>>;
  }>;
  total: { rows: number; writes: number; days: number }; // days = ceil(writes / dailyWriteCap)
}
```

**Write cost.** Each `affected` row costs 3 units (the row and 2 indexes). Each `package_advisories` row costs 2.

- At the planning figure of 2–4 million rows, the fill costs about 6–12 million units, plus 2 per record. At
  600,000 a day that is roughly 11–22 days.
- The real figure may be lower. `osv`, `debian` and `ubuntu` first-loads kept only their newest 10,000 records
  each.
- The dry run gives the actual number before anything is written. Nobody has measured it yet.

**Network.** Backfill sandboxes are created with
`network: { allowOut: [<API_BASE host>], denyOut: ({ allTraffic }) => [allTraffic] }` (Coordination 4). The job
reads and writes R2 only through the API's signed object routes (`client.ts`). It never uses presigned upload
URLs, which would need the R2 host.

**Runbook** (written into the job's header comment):

1. Deploy this change, with Coordination 1–5 in place.
2. **Refresh the lake.** For each package source, start `first-load`
   (`{ kind: 'first-load', sourceId, requestId, reason, url? }`).
   - Git sources need `url` set to the archive of the branch's head commit.
   - Send no `cursor`, so the source's cursor stays where it is.
   - Run them on days with no other first-load.
3. **Dry run.** Start `affected-backfill`. Read `jobs/<id>/counts.json`. `oldFormat` should be near 0 for the git
   sources. For `osv`, `debian` and `ubuntu` it counts records outside the refresh's newest 10,000.
4. **Fill.** Start the job once a day until every source is done. A second start on the same UTC day writes only
   the rest of that day's cap. Do not run it on a day a first-load is loading: the meter is shared.
5. **Check staging** (Acceptance criterion 14).

**Recovery.** If a run fails after logging `state written`, its chunks may not have been queued. Set that
source's `after` back to the run's logged `from`. Every write is idempotent.

## Tests

- **Parsers** (`packages/parsers/test/osv.test.ts`, `osv-sources.test.ts`), on the real fixtures:
  - `GHSA-9x82-4j54-863h`: one ECOSYSTEM entry, npm `isomorphic-git`, fixed `1.38.6`; summary set; severity
    `MODERATE`; reviewed.
  - `GO-2026-5006`: SEMVER, fixed `0.52.0`, reviewed. The same record with `review_status: 'UNREVIEWED'` is not
    reviewed.
  - `MAL-2026-12884` and `osv/MAL-2026-12900`: one SEMVER entry with no bounds (every version), no EXACT entry,
    not reviewed.
  - `DEBIAN-CVE-2026-97845`: one open entry per release (`Debian:12`, `Debian:13`, `Debian:14`); reviewed; no
    severity (its score is a CVSS vector).
  - `UBUNTU-CVE-2026-99315`: ecosystems such as `Ubuntu:Pro:14.04:LTS`; severity `MEDIUM`; at most 200 entries.
  - Inline records:
    - `last_affected` gives `lastAffected` and the display `'<= x'`;
    - two ranges, and two pairs in one range;
    - a GIT-only entry gives nothing;
    - a versions-only entry with 25 versions gives EXACT with all 25;
    - 1,001 versions give a display entry with no `rangeType`;
    - a withdrawn record keeps its entries with status `withdrawn`.
- **CVE List** (`cve-json5.test.ts`):
  - New fixture `fixtures/cve-list/registry-packages.json`: a real cvelistV5 record whose CNA `affected` has
    `collectionURL` and `packageName`, copied unchanged. `fixtures/cve-list/SOURCE.md` records its path and
    commit.
  - Inline variants, one per row of both tables in section 3: `pypi.org` with `lessThan`, `registry.npmjs.org`
    with `lessThanOrEqual`, a `crates.io` exact version, a Maven `group:artifact`, the `defaultStatus` +
    unaffected shape, `versionType: git` skipped, and a `github.com` entry dropped.
  - A record with no mapped entry gives exactly today's output.
- **No package entries** from NVD (`fixtures/nvd/CVE-2024-3400.json`, which has `configurations`), CSAF
  (`fixtures/red-hat/cve-2023-38545.json`) or CERT/CC (`fixtures/cert-cc/note-604762.json`): no entry has a
  `rangeType`.
- **Linker** (`packages/linker/src/affected.test.ts`):
  - `affectedRows` on the parsed fixtures: canonical ecosystems; PyPI `Foo_Bar` becomes `foo-bar`; Maven names
    kept; `Debian:12` kept; Hackage gives `unknown_ecosystem`.
  - `range_no` is per package; duplicate rows are dropped; a version with a space gives `bad_version`; a vendor
    entry gives `no_range_type`; the summary is cut to 300.
  - `packageWrites`:
    - a stored row with the same or a newer `modified` gives `[]`;
    - a newer version without one package gives deletes for exactly that package's keys;
    - a withdrawn version after an active one gives the status row and deletes for every stored range;
    - no packages and no stored row gives `[]`.
- **`link()`** (`link.test.ts`):
  - a cold record gets package rows;
  - linking it again with the first run's rows as stored gives no package rows;
  - a `cve-list` advisory with a fix on a stored hot vuln raises no `fix_released`;
  - each new table is read at most once;
  - `read` returning `[]` gives upserts and no deletes.
- **Schema** (`schema.test.ts`): `AFFECTED_COLUMNS`, `AFFECTED_KEY` and `PACKAGE_ADVISORY_COLUMNS` equal the
  `CREATE TABLE`s in migration 0002.
- **Loader** (new `apps/loader/src/inbox-tables.test.ts`): a chunk with `affected` upserts and deletes and
  `package_advisories` upserts passes `readChunk` and `planWrites`. Its cost is 3 per `affected` row (upsert or
  delete) and 2 per `package_advisories` row, matching `ROW_COST`.
- **Sandbox loads** (`load-shapes.test.ts`):
  - first-load drops package rows;
  - a change-list `big-file` keeps them;
  - an `archive` update drops them;
  - an update over 200,000 units drops them.
- **Backfill** (`e2b/jobs/src/jobs/affected-backfill.test.ts`, with `fakeApi`, no network, no DuckDB;
  `.ndjson.gz` parts):
  - The lake holds a GHSA part twice: an old-format copy (today's parser output, hand-written) and a new copy
    with a later job id. `raw/` holds a receipt whose item is a newer version of one record.
  - A fake fetch answering `1.1.1.1` fails the run with `egress not restricted`.
  - The first run writes `counts.json`, an empty manifest and `countedBy`. It writes no rows. `oldFormat` is 1.
  - A write run with a small cap:
    - never passes the cap;
    - never splits a record across chunks;
    - uses the raw copy where it is newer;
    - advances `after`.
  - A second run on the same day writes only the rest of the cap. A run on the next day resumes after `after`.
  - Walking to the end marks the source done. A newer lake part re-opens it and writes only that part's records.
  - Malformed state fails the run.
  - The time budget stops the walk and saves the state.
- **API** (`apps/api/test/internal-jobs.workers.test.ts`): `affected-backfill` starts as a global job, and its
  chunks are queued at `steady`.

## Not in scope

- Version comparers, the package-check route and its upgrade logic. That logic is what reads `reviewed`.
- Matching Debian and Ubuntu by release in the check route (Coordination 8).
- Loading all of OSV. The `osv`, `debian` and `ubuntu` first-loads keep their newest 10,000 records each.
- Turning CVSS vectors into scores.
- Keyed reads for sandboxes, so sandbox runs can delete stale ranges (Coordination 6).
- Fixing `big-file`'s lake writes (Coordination 7).
- Deleting rows when an upstream file is deleted rather than withdrawn. This is the same as `advisories` today.
- Cleaning summaries for agents: that happens on the way out.
- A cron for the backfill, and NVD or CSAF products as packages.

**Known limits:**

- **A short race.** A record that changes between a backfill run's read and the moment its chunks load can keep
  the older ranges until its next change. The window is one run plus queue time, which is hours.
- **No deletes in sandbox runs.** A record updated only through `big-file` keeps any range its new version
  dropped.
- **The 200-entry cap.** Ubuntu kernel records that list more than 200 package and release pairs are cut short.

## Acceptance criteria

1. `pnpm build`, `pnpm test`, `pnpm test:workers` and `pnpm typecheck` pass.
2. `git diff --name-only main` lists only the files in "What to build", their tests and the new fixture.
   `git diff main -- apps/api/src/lib/e2b.ts` touches only the two kind lists and their comment.
3. The parser tests in "Tests" pass on the named fixtures, including:
   - a MAL record means every version;
   - `last_affected` and full version lists survive as data;
   - the CVE List maps only the hosts in the table.
4. Writing the same record twice changes nothing: the second `link()` emits no package rows.
5. A record that drops a package removes exactly that package's `affected` rows, in the same output as the new
   rows.
6. A withdrawn or rejected record writes its status and deletes all of its stored `affected` rows.
7. `reviewedFix` matches the table in section 2, row by row, in a table-driven test.
8. NVD, CSAF and CERT/CC fixtures produce no package rows.
9. The loader accepts package chunks, and their planned cost is 3 and 2 units per row.
10. The backfill's dry run writes no rows and a complete `counts.json`. A write run stays under
    `DAILY_WRITE_CAP` across two runs on the same UTC day, keeps whole records per chunk, keeps the latest copy,
    resumes from `after`, and re-opens a done source when a newer lake part appears.
11. The backfill fails when it can reach `1.1.1.1`.
12. In first-load mode, and in update mode over the cap or from an archive, a sandbox load's inbox has no package
    rows, and the count is logged.
13. `pnpm --filter @ti/e2b-jobs bundle` succeeds and the bundle contains `affected-backfill`.
14. **Staging, by hand after merge, the refresh and the fill.** These cannot run in CI. Run each as
    `wrangler d1 execute ti_advisories_staging --remote` and save the output in the PR:
    - PyPI `langflow`: an active, reviewed record for `CVE-2025-3248` has a range with introduced `0` and fixed
      `1.3.0`. So 1.2.0 is covered.
    - Maven `org.apache.logging.log4j:log4j-core`: a record for `CVE-2021-44228` has a range covering 2.14.1
      (introduced `2.13.0`, fixed `2.15.0`).
    - A known `MAL-` npm package has a row with introduced `0` and no `fixed` or `last_affected`. The check route
      reads that row as every version.
    - `SELECT ecosystem, COUNT(*) FROM affected GROUP BY 1` (distro releases summed by base name) sits next to the
      dry run's `byEcosystem` and total, with the meter units the fill used.
    - The backfill job log shows the egress check passed.

## Coordination (requests to other owners, not edits in this change)

1. **Write rules, blocking.** After mcp-seams, `TABLES.get('affected').rule` must be `'upsert'` (an
   `OTHER_RULES` entry), and `package_advisories` must be `'newer'` on `modified`. Both should be in
   `WRITE_ORDER`. If `affected` is `none`, every write fails.
2. **Package helpers.** `canonicalEcosystem` must return `Debian`, `Ubuntu` and `Alpine` for those bare names.
   `normaliseName` must accept Debian and Ubuntu source package names unchanged. If not, distro rows only show up
   as skips in the dry run. Optional: word the `range_no` comment in migration 0002 as "position among this
   package's ranges in the record", if it is not yet applied.
3. **Backfill state, blocking.** In `apps/api/src/lib/presign.ts`, `allowedPrefixes('affected-backfill')` should
   add `lake/state/affected-backfill/`. Without it, no run can save its resume point or dry-run mark.
4. **Backfill egress, blocking for runs.** In `launcherFromEnv` (`e2b.ts`), sandboxes of kind
   `affected-backfill` should be created with
   `network: { allowOut: [new URL(API_BASE).host], denyOut: ({ allTraffic }) => [allTraffic] }`. Without it,
   the job's egress check fails every run.
5. **Collector write size, blocking for deploy.** Step 13 in `apps/collector/src/step.ts` should write
   `linked.rows` in calls of at most `MAX_ROWS_PER_CHUNK` rows. A 40-item step can now pass 500 rows, because one
   record may add up to 201, and `planWrites` throws above 500. Split between records where possible: each
   record's package rows sit next to each other. A split is still safe, because every row is idempotent and
   deletes touch only keys the new version no longer uses.
6. **Keyed sandbox reads, follow-up.** A sandbox route that returns stored `affected` key columns and
   `package_advisories.modified` for up to 100 `(source, source_id)` keys. Then `sandboxLinkDeps` can serve
   both reads, and sandbox runs can delete stale ranges.
7. **`big-file` lake writes, existing issue.** `presign.ts` lets only `first-load` write `lake/records/<source>/`,
   but `runLoad` writes lake parts in update mode too. So a `big-file` run with records looks set to fail on its
   first part. The backfill's re-open rule relies on update runs leaving lake parts once this is fixed.
8. **Check route.**
   - Distro rows are stored as `Debian:12`, `Ubuntu:22.04:LTS` and so on. Its `a.ecosystem = ?1` lookup will not
     find them until it handles releases (the purl `distro` qualifier carries one).
   - `vuln_key` is the record's own CVE or id, not the alias hub.
   - `reviewed` follows section 2.

## Decisions added at review

These settle the coordination items above, so the builder needs nothing from another branch.

- **Owned by this change after all:**
  - items 3 (backfill state prefix in `apps/api/src/lib/presign.ts`), 4 (backfill egress in `launcherFromEnv`
    in `apps/api/src/lib/e2b.ts`), 5 (collector write size in `apps/collector/src/step.ts`) and 7 (`big-file`
    lake writes in `presign.ts`). Build each as described there, with tests. `presign.ts` and `e2b.ts` are
    sensitive paths: keep the changes minimal and name them in the PR.
  - items 1 and 2 (write rules and package helpers) if `main` doesn't already have them when this change starts:
    `packages/db/src/table-info.ts` and the two helpers in `packages/core/src/packages.ts`.
- **Item 6** (keyed sandbox reads) stays a follow-up.
- **OS ecosystems keep their release,** exactly as OSV writes them (`Debian:12`, `Ubuntu:22.04:LTS`,
  `Alpine:v3.20`). The check route and the comparers use the same keys.
- **`vuln_key`** is the CVE the record names when it has one, else the record's own ID. That is what joins it
  to the hot-set tables.
- **Loading all of OSV, Debian and Ubuntu history** (beyond the newest 10,000 records each) is a separate change
  that follows this one. GitHub's advisory database, the main source for app ecosystems, is already loaded in
  full.
