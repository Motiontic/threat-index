# parsers-vendors: one CSAF 2.0 parser for Red Hat, Microsoft MSRC and Cisco advisories, and their pull config

## Why

Vendor advisories say which products a CVE hits and whether a fix shipped. Red Hat, Microsoft and Cisco all
publish CSAF 2.0 documents with a newest-first `changes.csv`, which is exactly what the `changelist` pattern
reads. Their source files exist but have no `parser` or `pull`, so every run ends `skipped`. This change
fills the `csaf` parser stub once, wires `red-hat`, `msrc` and `cisco` to it, and records why `oracle` stays
unwired (section 6). Cisco's openVuln API needs OAuth; its public CSAF directory does not, so it is used instead.

## Current state (checked on main, endpoints checked 23-24 Nov 2026)

| Area | Today |
| ---- | ----- |
| Source files | `red-hat.ts` (changelist, 3h, `on`, credit `Source: Red Hat Security Data (CC BY 4.0)`), `msrc.ts` (changelist, daily, `ask`), `cisco.ts` (changelist, 3h, `ask`), `oracle.ts` (changelist, daily, `ask`). None has `parser` or `pull` |
| `packages/parsers/src/csaf.ts` | A stub that throws `NotImplementedError`. `cve-json5.ts` exports `clip`, `toIso`, `asArray`, `asRecord` to reuse |
| `changelist` pattern | `listUrl` CSV, newest first; `timeColumn`/`refColumn` zero-based; `itemUrl` with `{ref}` (slashes in `ref` are kept as path segments). Up to 4 ranged reads of `rangeBytes` (default 64 KB). A server that ignores `Range` is read only to `rangeBytes`; if the cursor is not inside that, the run hands off a `big-file` job. No cursor yet: notes the newest line and hands off `first-load` (no history in a Worker). ≤ 40 items per step; an item that 404s arrives with `text: null`; item bodies over 5 MB hand off `big-file`. HEAD is sent only when the cursor has a validator |
| Item body | `ChangeItem { ref, time, text }` from `@ti/patterns/changelist` (`text` is the document's JSON text) |
| Linker | `advisories` stores `source, source_id, vuln_key, status, published, modified, url`. `affected` is not stored; an advisory whose `affected` has a `fixed` value marks the CVE's fix source (`fix_released` change). `exploited_wild` from a source other than `cisa-kev` is its own `signals` row |
| E2B | `first-load` and `big-file` jobs are still stubs on main; the hand-offs above are queued until they exist |

Endpoints (re-check in the sandbox, section 8):

- **Red Hat VEX.** `https://security.access.redhat.com/data/csaf/v2/vex/changes.csv`: `200 text/csv`, about 4.3 MB,
  weak ETag and Last-Modified, HEAD works, **`Range` ignored** (always `200`, full body). Lines are quoted:
  `"2022/cve-2022-38349.json","2026-11-23T21:57:08+00:00"`. Items:
  `https://security.access.redhat.com/data/csaf/v2/vex/<ref>`, one per CVE, `document.category` `csaf_vex`,
  `tracking.id` = the CVE, 25 KB to over 4.7 MB (CVE-2024-6387). Bulk regenerations happen (thousands of lines
  in an hour). Publisher namespace `https://www.redhat.com`. The RHSA feed (`.../v2/advisories/changes.csv`)
  also exists; it is not used here.
- **MSRC.** `https://msrc.microsoft.com/csaf/provider-metadata.json` lists `https://msrc.microsoft.com/csaf/advisories`
  and `/csaf/vex`. `https://msrc.microsoft.com/csaf/advisories/changes.csv`: `200`, about 560 KB, about 10,200
  lines, **no ETag or Last-Modified, HEAD answers `404`**, `Range` honoured (`206`). Quoted lines, newest first;
  a Patch Tuesday gives about 1,100 lines with the same timestamp. Bursts of requests get `429`. Items
  `https://msrc.microsoft.com/csaf/advisories/<ref>` (`2026/msrc_cve-2026-70197.json`), `csaf_security_advisory`,
  one CVE each, `tracking.id` `msrc_CVE-…`, namespace `https://msrc.microsoft.com`. Each vulnerability has a
  `threats` entry `{ category: 'exploit_status', details: 'Publicly Disclosed:No;Exploited:Yes;…' }`.
- **Cisco.** `https://www.cisco.com/.well-known/csaf/provider-metadata.json` (`csaf_trusted_provider`).
  `https://www.cisco.com/.well-known/csaf/changes.csv`: `200 text/csv`, about 178 KB, ETag, HEAD works,
  **`Range` ignored**. Unquoted lines `2026/cisco-sa-….json,2026-11-23T20:32:38Z`. Items
  `https://www.cisco.com/.well-known/csaf/<ref>`, `csaf_security_advisory`, one to many CVEs each, up to about
  1 MB, namespace `https://cisco.com`.
- **Oracle.** No `/.well-known/csaf/` (`404`), no index or `changes.csv`. Each quarterly Critical Patch Update has
  one CSAF file, `https://www.oracle.com/docs/tech/security-alerts/cpu<mon><yyyy>csaf.json` (301 to
  `/a/tech/docs/…`), 1.4 MB (Jan 2025) to 5.6 MB (Jul 2026), 267+ CVEs, namespace `https://www.oracle.com`,
  `distribution.text` "Copyright © Oracle. All rights reserved."

## What to build

Touch only: `packages/parsers/src/csaf.ts`, new tests in `packages/parsers/test/`, new files under
`fixtures/{red-hat,msrc,cisco,oracle}/`, and `packages/sources/src/sources/{red-hat,msrc,cisco,oracle}.ts`.
No dependency, lockfile, `load.ts`, registry, pattern, linker, app or migration change. Never change a
`licence` or `credit`.

### 1. Rules

- Worker-safe: no `node:` imports, `Buffer`, `process` or `require`. Validate with Zod `z.looseObject`.
- A malformed document throws an `Error` whose message starts with `csaf:`; one odd field never throws.
- Unknown fields go into `unknownFields` once each, never a crash (section 3 lists the known ones).
- IDs through `normaliseId`; store only IDs matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, else skip that
  vulnerability. Dates through `toIso`; signal days as `YYYY-MM-DD`. `url` only when it parses as http(s).
- Metadata only: no notes, descriptions, remediation text or scores are copied.

### 2. `packages/parsers/src/csaf.ts`

```ts
export const CSAF_PUBLISHERS: Readonly<Record<string, string>>; // namespace host -> source id
export const AFFECTED_MAX = 20;
export function parseCsaf(input: unknown, opts?: { source?: string }): ParseResult<AdvisoryRecord | SignalRecord>;
export const parse = (input: unknown) => parseCsaf(input);
```

- **Input:** a `ChangeItem` (`{ ref, time, text }`, recognised by shape as `cve-json5.ts` does for `GitFile`;
  `@ti/patterns` is not a dependency; `text: null` → no records), a CSAF object, or its JSON text.
  Bad JSON → `csaf: not valid JSON`; anything else → `csaf: expected a CSAF document, its JSON text or a change item`.
- **Shape:** `document.csaf_version` matches `^2\.`; `document.tracking` has string `id` and a parseable
  `current_release_date`; `document.publisher.namespace` is a URL. Otherwise throw `csaf: <path>: <issue>`.
  `tracking.status` `draft` → no records. No `vulnerabilities` (e.g. `csaf_base`) → no records.
- **Source:** `opts.source`, else `CSAF_PUBLISHERS[host of publisher.namespace]` with this map:
  `www.redhat.com`, `redhat.com` → `red-hat`; `msrc.microsoft.com`, `www.microsoft.com` → `msrc`; `cisco.com`,
  `www.cisco.com` → `cisco`; `www.oracle.com`, `oracle.com` → `oracle`. Unknown host → throw
  `csaf: unknown publisher <host>`. This keeps one parser name (`csaf`) for every vendor source.
- **Product names:** walk `product_tree.branches` recursively. Each branch `product` gives
  `id → { name, version, vendor }`: `version` is the `name` of the nearest ancestor-or-self branch whose
  category is `product_version`, `service_pack` or `patch_level`; `vendor` the nearest `vendor` branch name,
  else `publisher.name`. Then each `relationships[].full_product_name` and `product_tree.full_product_names`
  entry adds its id with its own name and the `version`/`vendor` of its `product_reference`.
- **Per vulnerability** with a `cve` that `isCve` (others are skipped, no error):
  - One `AdvisoryRecord`: `source`; `sourceId` = the CVE when `tracking.id` normalises to that CVE (Red Hat VEX),
    else `<tracking.id>:<CVE>` (one row per CVE, stable when an advisory gains CVEs); `vulnKey` the CVE;
    `status: 'active'`; `published` = the vulnerability's `release_date`, else `tracking.initial_release_date`;
    `modified` = `tracking.current_release_date`; `url` = the first http(s) `self` reference of the vulnerability,
    then of the document, whose path does not end `.json`, else the first document reference ending `.html`.
  - `affected` (omitted when empty): from `product_status`, in this order, deduplicated by `(name, range)`, at most
    `AFFECTED_MAX`: `fixed`, `first_fixed`, `recommended` → `{ ecosystem: vendor, name, fixed: version ?? name }`;
    `known_affected`, `first_affected`, `last_affected` → `range: 'affected'`; `under_investigation` →
    `range: 'under investigation'`; `known_not_affected` → `range: 'not affected'`. `name` and `fixed` are
    clipped to 200 characters; ids missing from the tree are skipped.
  - Exploitation: a `threats` entry with category `exploit_status` whose `details` matches `/\bExploited:\s*Yes\b/i`
    → one `SignalRecord { vulnKey: <CVE>, kind: 'exploited_wild', source, ref: <tracking.id>, firstSeen:
    <day of initial_release_date, else current>, evidenceDate: <day of current_release_date>, url }`.
    "Publicly Disclosed" is not an exploit signal. No other threat category emits a signal.

### 3. Known fields (anything else is reported as `<prefix>.<key>`)

- top: `document`, `product_tree`, `vulnerabilities`.
- `document`: `acknowledgments`, `aggregate_severity`, `category`, `csaf_version`, `distribution`, `lang`, `notes`,
  `publisher`, `references`, `source_lang`, `title`, `tracking`.
- `vulnerabilities[]`: `acknowledgments`, `cve`, `cwe`, `discovery_date`, `flags`, `ids`, `involvements`, `notes`,
  `product_status`, `references`, `release_date`, `remediations`, `scores`, `threats`, `title`.
- `product_status`: the eight CSAF 2.0 keys used in section 2. The product tree is not checked field by field.

### 4. Source config

- `red-hat.ts`: `parser: 'csaf'`, `pull.changelist = { listUrl:
  'https://security.access.redhat.com/data/csaf/v2/vex/changes.csv', timeColumn: 1, refColumn: 0, itemUrl:
  'https://security.access.redhat.com/data/csaf/v2/vex/{ref}', rangeBytes: 262_144 }`. A comment: the server
  ignores `Range`, so a run sees the newest 256 KB (about 4,600 changes); larger bursts hand off `big-file`.
- `msrc.ts`: `parser: 'csaf'`, `pull.changelist = { listUrl: 'https://msrc.microsoft.com/csaf/advisories/changes.csv',
  timeColumn: 1, refColumn: 0, itemUrl: 'https://msrc.microsoft.com/csaf/advisories/{ref}' }`,
  `rateLimit: { perMinute: 60 }`. A comment: no validator and HEAD 404s, so every daily run reads the head of the list.
- `cisco.ts`: `parser: 'csaf'`, `pull.changelist = { listUrl: 'https://www.cisco.com/.well-known/csaf/changes.csv',
  timeColumn: 1, refColumn: 0, itemUrl: 'https://www.cisco.com/.well-known/csaf/{ref}', rangeBytes: 262_144 }`.
  A comment: the public CSAF directory is used because openVuln needs OAuth; the whole list fits one read.
- `oracle.ts`: no `parser`, no `pull`; a comment says why (section 6).

### 5. Fixtures (`fixtures/<source>/`, each with a `SOURCE.md`: URL, date, licence, what was trimmed)

Fetch with curl in the sandbox. Trim each document with a small script that keeps the first few product ids
per `product_status` list and drops tree entries, relationships, scores and remediations no kept id uses (the
script is described in `SOURCE.md`). Keep every file under 40 KB. Hand-write only if a fetch fails, and say so.

- `red-hat/changes.csv`: first 12 lines; `red-hat/cve-2023-38545.json` (VEX with `fixed` and `known_not_affected`).
- `msrc/changes.csv`: first 12 lines; `msrc/msrc_cve-2024-38193.json` (`Exploited:Yes`, `fixed`);
  `msrc/msrc_cve-2026-70197.json` (`Exploited:No`).
- `cisco/changes.csv`: first 12 lines (unquoted); `cisco/cisco-sa-fmc-mulivulns-4psnfwvx.json` (5 CVEs).
- `oracle/cpujan2025csaf.json`: the January 2025 CPU cut to 3 vulnerabilities and their products; `SOURCE.md`
  records the copyright line and why the source is not wired.
- Hand-written in `fixtures/msrc/`: `draft.json` (`tracking.status: 'draft'`) and `no-cve.json` (one vulnerability
  without `cve`, one unknown document field).

### 6. Oracle (not wired, said in the PR)

Oracle has no CSAF index, `changes.csv` or provider metadata. Its only feed is one quarterly file whose URL
changes every quarter and whose size passes the 5 MB Worker body limit, so it needs the `heavy` pattern. That
pattern fetches a fixed `url`; following quarters needs a URL built from the version it reads, which is a
pattern change, and the `first-load`/`big-file` jobs that would parse it are stubs. The parser handles Oracle's
documents (test below), so wiring later is config only.

### 7. Tests (`packages/parsers/test/`, Node, fixtures through `fixture()`)

- `csaf.test.ts`:
  - Red Hat: `sourceId` is the bare CVE; `affected` has `fixed` entries first with `fixed` = the package version
    (`…el6sat.i686` style) and `ecosystem: 'Red Hat'`, then `not affected`; length ≤ `AFFECTED_MAX`; `url`
    is `https://access.redhat.com/security/cve/CVE-2023-38545`; no signal.
  - MSRC: 38193 gives an advisory `msrc_CVE-2024-38193:CVE-2024-38193` and one `exploited_wild` signal with the
    right days; 70197 gives no signal; `url` is the update-guide page, never the `.json`.
  - Cisco: five advisories `<tracking id>:<CVE>`, `url` the advisory page; Oracle: three advisories with
    `source: 'oracle'` and the `.html` CPU page as `url`.
  - Input forms: object, JSON text and `ChangeItem` give the same records; `text: null` gives none; bad JSON,
    a non-CSAF object, missing `current_release_date` and an unknown publisher throw `csaf:`; `draft.json` gives
    none; `no-cve.json` gives none and reports the unknown field; `opts.source` overrides the publisher map.
  - The changelist pattern end to end: `fetch` from `packages/patterns/src/changelist` with `makeCtx`, a cursor
    one line below the top of `red-hat/changes.csv` (served as `200`, ignoring `Range`) and `msrc/changes.csv`
    (served with `ranged()`), items served from the fixtures; every item parses.
- `sources-vendors.test.ts`: `loadParser('csaf')` works; the three pull blocks, `parser` and `rateLimit` equal
  section 4; `oracle` has neither; licence and credit values equal main's; `csaf.ts` has no `node:` import,
  `Buffer`, `process.` or `require(`.
- `link-vendors.test.ts`: the parsed fixtures through `link()` with `makeFake()` (as `link-sightings.test.ts`
  does, seeding the CVEs): one `advisories` row per `(source, sourceId)` with the CVE as `vuln_key`; the MSRC
  signal is its own `signals` row and `kev_added` stays null; a fixed Red Hat advisory sets the fix source.

## Not in scope

- Oracle ingestion (needs a versioned `heavy` URL and the E2B jobs); Oracle Security Alerts outside the CPU.
- Red Hat RHSA advisories (`/v2/advisories/`), MSRC `/csaf/vex`, the MSRC CVRF API and Cisco openVuln.
- History before the first cursor (`first-load`) and bursts over one read (`big-file`): queued, run when those jobs exist.
- Removed or withdrawn documents (`text: null` emits nothing; nothing is marked withdrawn yet), vulnerabilities
  without a CVE, CVSS scores, CWE, severity and remediation text from CSAF.
- `DATA_LICENSES.md`, the registry, patterns, linker, collector, E2B and API.

## Acceptance criteria

1. `pnpm build` passes (lint, typecheck, Node tests) and `pnpm test:workers` still passes.
2. `loadParser('csaf')` returns a module whose `parse` returns `{ records, unknownFields }` for all four fixtures.
3. The tests in section 7 pass using only fixtures; no test reaches the network.
4. `git diff --stat main` lists only the paths allowed in "What to build"; `pnpm-lock.yaml` and every
   `package.json` are unchanged; `rg "licence|credit" packages/sources/src/sources/{red-hat,msrc,cisco,oracle}.ts`
   matches main.
5. Each fixture folder has a `SOURCE.md` saying where each file came from, when, and what was trimmed or written.
6. Proof saved: `pnpm build` and `pnpm test:workers` output; for each wired list URL one curl showing status,
   content type, size, validator and how a `Range: bytes=0-1023` request is answered; the Oracle `404` for
   `/.well-known/csaf/provider-metadata.json`; the `link()` rows by table. The PR lists every endpoint check that
   differed from this spec.
