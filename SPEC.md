# parsers-osv: OSV parser and pull config for OSV.dev, GitHub Advisory Database, Debian and Ubuntu

## Why

Package advisories (which versions of which package are affected, and which version fixes it) come from the
OSV schema. OSV.dev republishes many databases in it (Go, PyPI, RustSec, malicious packages…), the GitHub
Advisory Database is written in it, and Debian and Ubuntu publish their per-CVE fix status as OSV feeds. Today
`packages/parsers/src/osv.ts` is a stub and the four source files have no `parser` and no `pull`, so the
collector skips them with "source has no pull config yet".

This change writes one OSV parser, three one-line wrappers that name the source, and the pull config for the
four sources, so the collector can run them on staging.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `packages/parsers/src/osv.ts` | Stub: `parse()` throws `NotImplementedError` |
| `packages/parsers/src/load.ts` | `loadParser(name)` imports `./<name>.ts`; a module must export `parse(input)` returning `ParsedRecord[]` or `ParseResult<ParsedRecord>` |
| Parser input | `apps/collector/src/step.ts` calls `parser.parse(item.body)` once per `RawItem`. The `changelist` pattern's body is `ChangeItem { ref, time, text: string \| null }`; the `git` pattern's body is `GitFile { path, status, previousPath?, text: string \| null }` (`text` is null for a removed or missing file). The parser is not told which source it runs for |
| `packages/sources/src/sources/osv.ts` | `changelist`, `3h`, `on`; no `parser`, no `pull` |
| `github-advisory-db.ts` | `git`, `3h`, `on`, credit "Source: GitHub Advisory Database (CC BY 4.0)"; no `parser`, no `pull` |
| `debian.ts`, `ubuntu.ts` | `changelist`, `3h`, `ask`, "fix status (through OSV)"; no `parser`, no `pull` |
| `PullConfig` (`packages/sources/src/pull.ts`) | `changelist { listUrl, timeColumn, refColumn, itemUrl, rangeBytes? }`; `git { repo, branch?, include }` |
| Records (`@ti/core/types`) | `AdvisoryRecord { source, sourceId, vulnKey, status, published?, modified, url?, affected? }`, `Affected { ecosystem, name, introduced?, fixed?, range? }`, `VulnRecord { key, kind: 'cve'\|'ghsa'\|'osv'\|'mal'\|…, title, summary, published?, modified, cwe, aliases, source, … }` |
| Linker | An advisory's IDs are its `sourceId` and `vulnKey`; a vuln's are its `key` and `aliases`. A CVE among them becomes the hub. `affected[].fixed` sets the flaw's fix source |
| Fixtures | `fixtures/osv/` holds `pattern-*` files for the changelist tests only; keep them |

Endpoints, checked on 24 Nov 2026:

- `https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv`: 206 to a `Range` request, ETag, ~166 MB,
  newest first, lines `<RFC 3339 time with nanoseconds>,<ecosystem>/<id>`. Ecosystem names can contain spaces
  (`Docker Hardened Images/DHI-…`). The first 256 KB held 5,346 lines covering about 40 minutes, mostly Red Hat,
  GIT and Docker Hardened Images.
- `…/Debian/modified_id.csv` (~3.9 MB) and `…/Ubuntu/modified_id.csv` (~3.7 MB): lines `<time>,<id>`; ids are
  `DEBIAN-CVE-*`, `DSA-*`, `DLA-*` and `UBUNTU-CVE-*`, `USN-*`. The first 256 KB covers about three days.
- Records: `…/<ecosystem>/<id>.json`, for example `…/Go/GO-2026-5006.json`, `…/Debian/DEBIAN-CVE-2026-97845.json`.
  Debian and Ubuntu records carry their CVE in `upstream`, not `aliases`. One `UBUNTU-CVE-*` record for a
  kernel flaw was 693 KB with 268 `affected` entries.
- `github/advisory-database`: default branch `main`, CC-BY-4.0, one commit per published advisory, files at
  `advisories/github-reviewed/<yyyy>/<mm>/<GHSA-id>/<GHSA-id>.json` (raw file 200).

## What to build

Touch only: `packages/parsers/src/{osv,osv-ghsa,osv-debian,osv-ubuntu}.ts`, new tests under
`packages/parsers/test/`, `fixtures/{osv,github-advisory-db,debian,ubuntu}/` (add files; keep the existing
`pattern-*` files) and `packages/sources/src/sources/{osv,github-advisory-db,debian,ubuntu}.ts`. No other source
files, no shared contract files, no migrations, no new dependencies (`zod` is already a parsers dependency).

### 1. `packages/parsers/src/osv.ts`

```ts
export interface OsvProfile {
  /** Written into every record's `source`. */
  source: string;
  /** Whether this profile keeps a record. `ecosystems` are base names (text before the first ':'). */
  keep(id: string, ecosystems: readonly string[]): boolean;
}
export const MAX_AFFECTED = 200;
/** Language package ecosystems the `osv` source keeps. */
export const LANGUAGE_ECOSYSTEMS: ReadonlySet<string>;
export function parseOsv(input: unknown, profile: OsvProfile): ParseResult<VulnRecord | AdvisoryRecord>;
/** The `osv` source's profile. */
export function parse(input: unknown): ParseResult<ParsedRecord>;
```

**Input.** Accept a `ChangeItem` (`{ ref, time, text }`), a `GitFile` (`{ path, status, text }`), a JSON string or
an already parsed OSV object. `text: null` or a git `status: 'removed'` returns `{ records: [], unknownFields: [] }`
(deleting withdrawn records is left for later). Bad JSON, a non-object, a missing or unsafe `id`
(`/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/`) or a missing or invalid `modified` throws; the collector counts that
item as failed. No Node-only imports: the same code runs in Workers and E2B.

**Ecosystems.** The base names of every `affected[].package.ecosystem` (`Debian:12` → `Debian`), plus, for a
`ChangeItem` whose `ref` contains `/`, the text before the first `/`. `profile.keep(id, ecosystems)` false →
no records.

**Dates.** OSV times have up to nine fraction digits. Truncate the fraction to milliseconds and output UTC
`YYYY-MM-DDTHH:MM:SS.sssZ`. An invalid `published` is left out.

**One `AdvisoryRecord` per kept OSV record:**

- `source` = `profile.source`; `sourceId` = `normaliseId(id)`.
- `vulnKey`: the first CVE (by `isCve`) in `aliases`, then in `upstream`, normalised; otherwise `null`.
- `status`: `'withdrawn'` when `withdrawn` is set, else `'active'`.
- `published`, `modified` as above.
- `url`: a GHSA id → `https://github.com/advisories/<id>`; else the first `references[]` entry of type
  `ADVISORY` with an http(s) URL; else `https://osv.dev/vulnerability/<id>`.
- `affected`: for each `affected[]` with a `package.name` and `package.ecosystem`, walk each range of type
  `SEMVER` or `ECOSYSTEM` (skip `GIT`: commit hashes are not versions) through its `events` in order.
  `introduced` opens a pair (`"0"` means no lower bound: leave `introduced` out); `fixed` closes it with `fixed`;
  `last_affected` closes it with `range: "<= <v>"`; `limit` is ignored; a pair still open at the end has no
  `fixed`. A package with no usable range but a `versions` list gives one entry with `range` = the first 20
  versions joined by `", "`, plus `" (+N more)"` when cut. Drop exact duplicates and keep at most
  `MAX_AFFECTED` entries, in input order.

**Plus one `VulnRecord` when `vulnKey` is null and the record is not withdrawn:**

- `key` = `normaliseId(id)`; `kind`: `GHSA-…` → `'ghsa'`, `MAL-…` → `'mal'`, anything else → `'osv'`. Malicious
  package entries stay `'mal'` even when they have a GHSA alias.
- `title`: `summary`, else the first line of `details`, else the id; at most 200 characters.
- `summary`: `summary`, else `details`, whitespace collapsed, at most 300 characters (cut with `…` inside 300).
- `published`, `modified` as above; `cwe`: `database_specific.cwe_ids` (GitHub) or `database_specific.cwes[].cweId`
  (malicious packages), unique, only strings matching `/^CWE-\d+$/`.
- `aliases`: `aliases` then `upstream`, normalised, unique, without the record's own id. `related` is not an alias.
- `source` = `profile.source`. Leave the CVSS fields out (a vector needs a calculator; later).

**Unknown fields.** Report top-level keys outside the OSV 1.7 set (`schema_version`, `id`, `modified`,
`published`, `withdrawn`, `aliases`, `upstream`, `related`, `summary`, `details`, `severity`, `affected`,
`references`, `credits`, `database_specific`) by name; unknown keys of an `affected[]` entry as
`affected.<key>`; of a range as `affected.ranges.<key>`; of an event as `affected.ranges.events.<key>`. Never
look inside `database_specific` or `ecosystem_specific`. Never throw for an unknown field.

**The `osv` profile** (`parse`): `source: 'osv'`; keep a record when its id does not start with `GHSA-` (the
`github-advisory-db` source owns those), it has at least one ecosystem, and every ecosystem is in
`LANGUAGE_ECOSYSTEMS`: `npm`, `PyPI`, `Go`, `crates.io`, `Maven`, `NuGet`, `RubyGems`, `Packagist`, `Pub`, `Hex`,
`Hackage`, `GHC`, `CRAN`, `Julia`, `SwiftURL`, `GitHub Actions`, `OSS-Fuzz`, `opam`, `VSCode`. Linux
distributions, container images and vendor feeds re-published by OSV.dev (Debian, Ubuntu, Red Hat, Alpine, SUSE,
Docker Hardened Images…) are dropped: they have their own sources and licence statuses, or none yet.

### 2. Wrapper parsers

Each file is a few lines: `export function parse(input: unknown) { return parseOsv(input, PROFILE); }`.

| File | `source` | Keeps |
| ---- | -------- | ----- |
| `osv-ghsa.ts` | `github-advisory-db` | ids starting `GHSA-` |
| `osv-debian.ts` | `debian` | ids starting `DEBIAN-CVE-` |
| `osv-ubuntu.ts` | `ubuntu` | ids starting `UBUNTU-CVE-` |

Debian `DSA`/`DLA`/`DTSA` and Ubuntu `USN` notices are skipped: one notice bundles many CVEs, an advisory has
one `vulnKey`, and the per-CVE records already carry the same fixed versions. Notice-level records are later work.

### 3. Source config

Set `parser` and `pull` in each file. Don't change any other field, and never the licence.

| Source | `parser` | `pull` |
| ------ | -------- | ------ |
| `osv` | `osv` | `changelist: { listUrl: 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv', timeColumn: 0, refColumn: 1, itemUrl: 'https://osv-vulnerabilities.storage.googleapis.com/{ref}.json' }` |
| `github-advisory-db` | `osv-ghsa` | `git: { repo: 'github/advisory-database', branch: 'main', include: ['advisories/github-reviewed/**/*.json'] }` |
| `debian` | `osv-debian` | `changelist: { listUrl: '…/Debian/modified_id.csv', timeColumn: 0, refColumn: 1, itemUrl: '…/Debian/{ref}.json' }` |
| `ubuntu` | `osv-ubuntu` | `changelist: { listUrl: '…/Ubuntu/modified_id.csv', timeColumn: 0, refColumn: 1, itemUrl: '…/Ubuntu/{ref}.json' }` |

(`…` = `https://osv-vulnerabilities.storage.googleapis.com`; write the full URLs.) Unreviewed GitHub advisories are
left out: they are mostly CVE mirrors with no package data. Add a short comment in `osv.ts` (the source file)
saying that the global list changes faster than four 64 KB ranges cover in three hours, so most runs hand off to
E2B as `big-file` until a per-ecosystem fan-out exists; that is expected, not an error.

Before committing, check each URL from the sandbox with `curl -sI` (list URLs with `-r 0-511`) and save the
status lines as proof. If the sandbox cannot reach a host, say so in the PR; don't guess.

### 4. Fixtures

Fetch real records with `curl` and trim them; if a host is unreachable, hand-write records with the same shape
and say so in `SOURCE.md`. Each folder gets a `SOURCE.md` (URL, fetch date, licence, what was trimmed).

- `fixtures/osv/`: `GO-2026-5006.json` (CVE + GHSA aliases, SEMVER range, `related`); `MAL-2026-12900.json`
  (malicious package with a GHSA alias); hand-written `no-cve.json` (a `RUSTSEC-` id, no aliases, two
  introduced/fixed pairs, a `last_affected` range, a `GIT` range and one unknown top-level key);
  `withdrawn.json`; `bad.json` (no `id`). Add the new files to the existing `fixtures/osv/` and keep its
  `pattern-*` files and `PATTERNS.md`.
- `fixtures/github-advisory-db/`: `GHSA-9x82-4j54-863h.json` from the raw GitHub URL above; hand-written
  `GHSA-no-cve.json` with `database_specific.cwe_ids`.
- `fixtures/debian/`: `DEBIAN-CVE-2026-97845.json`, `DSA-6654-1.json`.
- `fixtures/ubuntu/`: `UBUNTU-CVE-2026-99315.json` trimmed to 3 `affected` entries; `USN-9176-1.json`.

### 5. Tests (`packages/parsers/test/osv.test.ts`, `osv-sources.test.ts`; Node, no network)

- Each fixture through its parser: exact record counts, `vulnKey`, `status`, `url`, `affected` pairs, VulnRecord
  `kind`, `aliases`, `cwe`, and millisecond dates.
- The same record as a `ChangeItem`, a `GitFile`, a JSON string and an object gives equal output.
- `text: null`, `status: 'removed'`, a dropped ecosystem (`Red Hat/RHSA-…`), a `GHSA-` id under the `osv`
  profile, and `DSA`/`USN` ids under their wrappers each give no records.
- `bad.json` and invalid JSON throw; unknown fields are listed, not thrown.
- A synthetic record with 300 affected packages keeps `MAX_AFFECTED`.
- `loadParser` resolves `osv`, `osv-ghsa`, `osv-debian`, `osv-ubuntu`.
- `osv-sources.test.ts`: for the four sources (from `SOURCE_BY_ID`), the parser loads, the `pull` block matches
  the pattern, and the licences are still `osv: on`, `github-advisory-db: on`, `debian: ask`, `ubuntu: ask`.
  Run the changelist pattern's `check()` for `debian` with a stub `fetch` answering 304 to its ETag and expect
  `'unchanged'`.

## Not in scope

- Debian/Ubuntu notice records (DSA, DLA, USN), unreviewed GitHub advisories, and OSV ecosystems outside
  `LANGUAGE_ECOSYSTEMS`.
- `openssf-malicious-packages` (its own repo and milestone); its `MAL-` records arrive through `osv` meanwhile.
- CVSS scores from vectors, `credits`, `references` beyond the URL, `ecosystem_specific` data.
- Deleting withdrawn or removed records, an E2B job for the OSV list, per-ecosystem fan-out, any change to
  patterns, the collector, the linker, the registry or other sources.

## Acceptance criteria

1. `pnpm build` (lint, typecheck, `pnpm test`) and `pnpm test:workers` pass; save both outputs.
2. `osv.ts` exports `parseOsv`, `parse`, `OsvProfile`, `MAX_AFFECTED` and `LANGUAGE_ECOSYSTEMS` as in section 1;
   the three wrappers exist and each is a single call to `parseOsv`.
3. The tests in section 5 pass, on fixtures only; no test makes a network request.
4. `git diff --stat main -- packages/sources/src` shows only the four source files, and in each only `parser`
   and `pull` changed (paste the diff in the PR).
5. Proof saved: the `curl` status lines for every URL in section 3 (or a note that the host was unreachable),
   and a table of fixture → records produced (count, kinds, `vulnKey`).
6. No Node-only import under `packages/parsers/src` (`rg "from 'node:" packages/parsers/src` is empty).
