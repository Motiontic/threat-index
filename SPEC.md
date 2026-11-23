# parsers-attack: MITRE ATT&CK and ATLAS technique parser, OpenSSF malicious-package wrapper, and pull config

## Why

The `techniques` table (`ti_world`) has rows only for CWE and CAPEC today. The two catalogues people use to describe
how attackers work, MITRE ATT&CK (enterprise) and MITRE ATLAS (attacks on AI systems), have source files, but those
files have no `parser` or `pull`, so every run ends `skipped`. OpenSSF's malicious-packages repo, where malicious
package reports start, has a source file in the same state. This change fills in `packages/parsers/src/stix.ts` (one
STIX 2.1 parser serves both MITRE catalogues), adds `osv-malicious.ts` (an OSV profile like `osv-ghsa.ts`), and
sets `parser` and `pull` in `mitre-attack.ts`, `mitre-atlas.ts` and `openssf-malicious-packages.ts`.

## Current state (checked on main, endpoints checked 24 Nov 2026)

| Area | Today |
| ---- | ----- |
| Source files | `mitre-attack.ts` and `mitre-atlas.ts`: pattern `heavy`, weekly, licence `on`, `heavy: true`, credits set. `openssf-malicious-packages.ts`: pattern `git`, `3h`, licence `on`. None has `parser` or `pull` |
| `packages/parsers/src/stix.ts` | A stub that throws `NotImplementedError('parser stix')` |
| Models to copy | `cwe.ts` (`TechniqueRecord`s, `clip`/`SUMMARY_MAX` from `cve-json5.ts`, returns `{ records, unknownFields, version }`); `osv-ghsa.ts` (a three-line OSV profile) |
| `TechniqueRecord` | `{ id, framework: 'attack' \| 'atlas' \| 'cwe' \| 'capec', name, parent?, summary? }`. The linker upserts `techniques` rows keyed by `id`; there is no `modified`, a row is written only when it differs |
| `vuln_techniques` | Table exists (`vuln_key`, `technique_id`, `origin` default `'source'`), but no `ParsedRecord` type carries a link and the linker never writes the table |
| `heavy` pattern | Reads `pull.heavy.version` (a Range GET of `bytes`, default 4096, regex group 1) or else a HEAD validator. On change it hands off a job of `pull.jobKind`, default `big-file`. `big-file` is a stub; use `first-load` |
| `first-load` job (E2B) | Downloads the URL, `JSON.parse`s it when the path ends `.json`, else passes text; calls the source's parser; links; writes inbox and lake. It does not unpack archives |
| `git` pattern | With no cursor, or with more than 300 changed files, it hands off a `first-load`/`big-file` job for the repo's archive. Otherwise it fetches each changed file that matches `include` and hands the parser a `GitFile` `{ path, status, text }` (`text` null when removed) |
| `osv.ts` | `parseOsv(input, profile)` accepts a `GitFile`, a JSON string or an object; `removed` gives no records; `MAL-` ids with no CVE become `VulnRecord` kind `mal` plus an `AdvisoryRecord`. The `osv` source already keeps `MAL-` records it reads from OSV.dev |

Facts checked with curl on 24 Nov 2026 (re-check in the sandbox, acceptance 5):

- **ATT&CK.** `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`,
  55,277,605 bytes, strong ETag, honours `Range` (206). A STIX bundle `{ type: 'bundle', id, objects }`. The first
  object is the `x-mitre-collection`; `"x_mitre_version": "20.1"` sits within the first 600 bytes. Object types:
  `relationship`, `x-mitre-analytic`, `attack-pattern` (867), `malware`, `x-mitre-detection-strategy`,
  `course-of-action`, `intrusion-set`, `x-mitre-data-component`, `tool`, `campaign`, `x-mitre-data-source`,
  `x-mitre-tactic`, `x-mitre-collection`, `x-mitre-matrix`, `identity`, `marking-definition`. Of 867 techniques,
  149 are `revoked: true` and 12 `x_mitre_deprecated: true`; 706 remain, all with a unique id matching
  `^T\d{4}(\.\d{3})?$` in the first `external_references` entry (`source_name: 'mitre-attack'`). Descriptions are
  Markdown with `(Citation: …)` markers and `[text](/techniques/T1234)` links; the longest is 4,668 characters.
- **ATLAS.** The old `dist/ATLAS.yaml` is frozen at 5.6.0 and marked deprecated; `dist/v6/ATLAS-latest.yaml` is a
  symlink that raw GitHub serves as its 18-byte target name. Each release (latest `v2026.10`, 28 Oct 2026) publishes
  `stix-atlas.json` (1,587,795 bytes) as an asset, so
  `https://github.com/mitre-atlas/atlas-data/releases/latest/download/stix-atlas.json` is a stable URL (two 302s,
  then 200). Same bundle shape as ATT&CK: 221 `attack-pattern`s, none revoked or deprecated, ids
  `^AML\.T\d{4}(\.\d{3})?$` in `external_references[0]` (`source_name: 'mitre-atlas'`); some also cite an ATT&CK id
  in a later reference. The collection's `x_mitre_version` (`2026.10`) is at the end of the file, so the version
  comes from `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml`, whose first line is
  `- release: '2026.10'` (Range works).
- **OpenSSF.** `ossf/malicious-packages`, branch `main`, Apache-2.0. Records are OSV JSON at
  `osv/malicious/<ecosystem>/<package>/MAL-YYYY-N.json`; withdrawn ones move to `osv/withdrawn/<ecosystem>/…` with a
  `withdrawn` time. Temporary files named `MAL-0000-<origin>-<hash>.json` appear and are later replaced by an
  allocated id. `osv/malicious/.id-allocator` and `README.md` are not records.
- **No vuln-to-technique data.** ATT&CK names CVEs only inside citations (10 technique references named
  `NVD CVE-…`), not as a mapping; ATLAS's STIX has no CVE fields; malicious-package records carry only `CWE-506`.
  So this change writes no `vuln_techniques` rows (section 5).

## What to build

### 1. `packages/parsers/src/stix.ts`

```ts
export function parseStix(input: unknown): ParseResult<TechniqueRecord> & { version?: string };
export const parse = parseStix;
```

- Input: a parsed object or a JSON string (parse it; bad JSON throws `stix: invalid JSON` with the cause). Anything
  but `{ type: 'bundle', objects: [...] }` throws `stix: expected a STIX bundle`.
- Frameworks, by `external_references[].source_name`: `mitre-attack` → `attack` with id `^T\d{4}(\.\d{3})?$`;
  `mitre-atlas` → `atlas` with id `^AML\.T\d{4}(\.\d{3})?$`. Take the first reference that matches either; an
  `attack-pattern` with none is skipped (mobile and ICS ATT&CK ids use other source names and are skipped too).
- Skip objects with `revoked === true` or `x_mitre_deprecated === true`, and any without a non-empty string `name`.
- `name`: trimmed, whitespace collapsed, `clip(name, 200)`.
- `summary`: from `description`: remove `(Citation: …)` markers, turn `[text](url)` into `text`, drop HTML tags,
  then `clip(…, SUMMARY_MAX)` (300). Omit when empty. Never store the full description.
- `parent`: for a dotted id (`T1566.001`, `AML.T0000.001`) the text before the last `.`, set only when that id is
  also emitted from the same bundle (two passes). No other relationship objects are read.
- Duplicate ids (a re-issued technique): keep the object with the later `modified`; equal → the later one in file order.
- `version`: the `x_mitre_version` of the first `x-mitre-collection` object, when it is a string.
- `unknownFields`: `type:<t>` for each object type not in the known list (the 16 ATT&CK types above, plus ATLAS's
  same set), once each, sorted. Never a crash.
- Limits: more than 5,000 emitted techniques throws `stix: too many techniques` (a wrong file, not a catalogue).
  No Node-only imports; output order is file order.

### 2. `packages/parsers/src/osv-malicious.ts`

```ts
const PROFILE: OsvProfile = {
  source: 'openssf-malicious-packages',
  keep: (id) => id.startsWith('MAL-') && !id.startsWith('MAL-0000-'),
};
export function parse(input: unknown) { return parseOsv(input, PROFILE); }
```

`MAL-0000-…` files are placeholders that vanish once an id is allocated; keeping them would leave orphan rows.
Do not edit `osv.ts` (the `osv` source keeps reading `MAL-` records from OSV.dev; see section 5).

### 3. Source files (only these three)

- `mitre-attack.ts`: add `parser: 'stix'`, and
  `pull: { heavy: { url: '<ATT&CK URL above>', version: { url: '<same URL>', pattern: '"x_mitre_version":\\s*"([\\d.]+)"', bytes: 2048 } }, jobKind: 'first-load' }`.
- `mitre-atlas.ts`: add `parser: 'stix'`, and
  `pull: { heavy: { url: 'https://github.com/mitre-atlas/atlas-data/releases/latest/download/stix-atlas.json', version: { url: 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml', pattern: "release: '([\\d.]+)'", bytes: 256 } }, jobKind: 'first-load' }`.
  Add a comment: the manifest can name a release a few minutes before its asset exists; the next weekly run
  catches up.
- `openssf-malicious-packages.ts`: add `parser: 'osv-malicious'`, `credit: 'Source: OpenSSF Malicious Packages (Apache-2.0)'`,
  `pull: { git: { repo: 'ossf/malicious-packages', branch: 'main', include: ['osv/malicious/**/*.json', 'osv/withdrawn/**/*.json'] } }`.

Patterns, cadence, `heavy` and licence statuses stay as they are.

### 4. Fixtures (each folder gets a `SOURCE.md`: URL, fetch date, what was trimmed, what is hand-written)

- `fixtures/mitre-attack/enterprise-sample.json`: cut from the real file (fetch it with curl in the sandbox; if
  that fails, hand-write the same shape and say so): the collection object with `x_mitre_contents` cut to 3
  entries, `T1190`, `T1566`, `T1566.001`, `T1566.002`, one revoked and one deprecated `attack-pattern`, one each
  of `x-mitre-tactic`, `relationship`, `malware`, `x-mitre-analytic`. Keep real descriptions (one has citations).
- `fixtures/mitre-attack/pattern-version.json`: the real first 2,048 bytes of the file.
- `fixtures/mitre-atlas/stix-sample.json`: cut from the release asset: the collection, `AML.T0000`, `AML.T0000.000`,
  `AML.T0051` and one of its sub-techniques, a tactic, a `subtechnique-of` relationship, a `course-of-action`;
  plus a hand-added object of type `x-example-new` (say so).
- `fixtures/mitre-atlas/pattern-manifest.yaml`: the real first 256 bytes of `manifest.yaml`.
- `fixtures/openssf-malicious-packages/`: `MAL-2026-12884.json` (real, from
  `osv/malicious/npm/bnpl-blocks-atom-bnpl-notification/`, `details` cut to 600 characters); `MAL-0000-placeholder.json`
  and `withdrawn.json` (hand-written, invented text, the second with a `withdrawn` time).

### 5. Tests (`packages/parsers/test/stix.test.ts`, `packages/parsers/test/sources-attack.test.ts`)

- ATT&CK sample: exactly the 4 kept techniques; `T1190` equals a full expected record (framework `attack`, no
  parent, summary ≤ 300 with no `(Citation:` and no `](`); `T1566.001.parent === 'T1566'`; revoked and deprecated
  absent; `version === '20.1'`; `unknownFields` empty.
- ATLAS sample: framework `atlas`, sub-technique parents, `version === '2026.10'`, `unknownFields` equals
  `['type:x-example-new']`.
- Edge cases inline: JSON string input; non-bundle throws; bad JSON throws; a sub-technique whose parent is absent
  gets no `parent`; duplicate ids keep the later `modified`; a 3,000-character description clips to ≤ 300; an
  `attack-pattern` with only a `mitre-mobile-attack` reference is skipped; 5,001 techniques throws.
- `osv-malicious`: the real file gives a `mal` vuln (`source: 'openssf-malicious-packages'`, `cwe: ['CWE-506']`)
  and an advisory; as a `GitFile` with `status: 'removed'` → no records; the placeholder → no records; the
  withdrawn file → one advisory with status `withdrawn` and no vuln; a `GHSA-` record → no records.
- Sources: each of the three has the `parser` and `pull` above (`toEqual`), and `loadParser` loads it. Using
  `makeCtx`/`route`/`reply` from `packages/patterns/test/helpers.ts` (as `osv-sources.test.ts` does), the `heavy`
  pattern's `fetch` on the two pattern fixtures hands off `{ kind: 'first-load', url: <heavy url> }` with cursor
  value `20.1` / `2026.10`, and returns unchanged when the cursor already holds that value.

### 6. What this does not link

No `vuln_techniques` rows: none of these sources maps a CVE or CWE to a technique, and no `ParsedRecord` type can
carry such a link. Adding one (a link record in `@ti/core/types` plus a linker branch) and deriving links by our own
rule (CAPEC's ATT&CK mappings, `origin: 'rule'`) is later work owned by the core and linker. `MAL-` ids arrive from
both `osv` and this source: the `vulns` row is shared (newer `modified` wins) and each source keeps its own
`advisories` row. Choosing one owner for `MAL-` ids is a later decision.

## Not in scope

ATT&CK mobile and ICS bundles; tactics, mitigations, groups, software, campaigns and detections; ATLAS case studies
(possible `IncidentRecord`s later); dropping techniques that become revoked after they were stored (rows stay);
the OpenSSF first load and >300-file bursts (both hand off a repo archive, which `first-load` cannot unpack yet);
any API route or web page for techniques; edits to `osv.ts`, the linker, `@ti/core`, migrations, other apps or
other sources' files.

## Acceptance criteria

1. `packages/parsers/src/stix.ts` and `osv-malicious.ts` exist with the exports above; `rg NotImplementedError
   packages/parsers/src/stix.ts` finds nothing.
2. The three source files carry exactly the `parser` and `pull` in section 3; nothing else in `packages/sources`
   changes. `git diff --stat main` lists only the files named in sections 1–5.
3. `pnpm build` and `pnpm test:workers` pass. Save both outputs.
4. Every fixture folder has a `SOURCE.md` saying which files are real (URL, date, trims) and which are hand-written.
5. Endpoint proof, saved: `curl -sI` (status, length, ETag) for the ATT&CK URL and the ATLAS release URL with `-L`;
   `curl -s -r 0-2047` on the ATT&CK URL showing the version line; `curl -s -r 0-255` on `manifest.yaml`. If a
   fact above has changed (URL, layout, version position), fix the config and say what changed.
6. Full-file proof, saved: with a temporary, uncommitted test or script, run `parseStix` on the real ATT&CK file
   and the real ATLAS asset and record counts, `version`, `unknownFields`, the longest `summary` length, and how
   many records have a `parent`. Expect about 706 ATT&CK and 221 ATLAS techniques; explain any large difference.
   Run `osv-malicious` on 5 real files from different ecosystems and record the output.
7. If `e2b/jobs/src/jobs/first-load.ts` is implemented on `main` when you start, run
   `pnpm --filter @ti/e2b-jobs bundle` and save `grep -c parseStix e2b/jobs/dist/run.mjs` (≥ 1); otherwise say so.
8. No full description text is stored: every emitted `summary` is ≤ 300 characters (asserted in a test).
