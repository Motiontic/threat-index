# parsers-exploits: Exploit-DB, Metasploit, Nuclei and PoC-in-GitHub parsers and pull config

## Why

"Is there a public exploit, a scanner check or a proof of concept?" is the question after "is it exploited in the
wild?". Four sources answer it, but their source files have no `parser` and no `pull`, so every collector run ends
`skipped: source has no pull config yet`. This change adds one parser per source, emitting `SignalRecord`s of kind
`public_exploit` (Exploit-DB, Metasploit), `detection` (Nuclei, Metasploit scanners) and `poc` (PoC-in-GitHub), and
fills the pull config, so the collector runs them on staging. Records carry metadata only (reference, date, link,
CVE); exploit code is never fetched or stored.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| Source files | `exploit-db.ts` (git, 3h, `ask`), `metasploit.ts` (git, 3h, `on`), `nuclei-templates.ts` (git, 3h, `on`), `poc-in-github.ts` (git, 3h, `on`). None has `parser` or `pull` |
| `PullConfig` (`packages/sources/src/pull.ts`) | `git { repo, branch?, include }` is **GitHub only**; `heavy { url, version? }` reads a validator (HEAD ETag) and hands the file to E2B; `jobKind` defaults to `big-file` |
| `git` pattern | Body per changed file: `GitFile { path, status, previousPath?, text }` (`text` null when removed). Fetches only `.json .csv .md .xml .yaml .yml .txt`. A file over 5 MB → `big-file` job for its raw URL. A first run (no cursor) → `first-load` job with the repo's `archive/<sha>.tar.gz` |
| `heavy` pattern | No items; the collector starts the job before any parser runs. `cwe.ts`/`capec.ts` are the model: `pattern: 'heavy'`, `heavy: true`, `pull.heavy` |
| E2B jobs | `first-load` (planned) downloads `job.url ?? pull.heavy.url`, passes `JSON.parse(text)` for `.json`, else the text, to `parse()`. `big-file` is a stub |
| Records | `SignalRecord { vulnKey, kind, source, ref, firstSeen, evidenceDate?, url? }`. Linker: keyed by (`vuln_key`, `kind`, `source`, `ref`), keeps the earliest `firstSeen`, needs a valid date; `public_exploit` promotes a CVE into the hot set |
| Model parsers | `kev.ts` (Zod `looseObject`, known-field set), `osv.ts` and `cve-json5.ts` (accept a `GitFile`, a string or an object; `clip`, `toIso` helpers) |
| Tests that name these sources | `packages/linker/src/link.test.ts`, `apps/api/test/public-api.workers.test.ts` use `metasploit` as a label only. Leave them |

Endpoints, checked on 24 Nov 2026:

- Exploit-DB: `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`: 200, `text/plain`,
  10,376,219 bytes, ETag (MD5); `If-None-Match` gives 304; `Range` gives 206. The repo is on **GitLab**, which the
  `git` pattern does not support. 47,182 rows, sorted by platform (not date); 30,278 rows name ≥ 1 CVE (33,907
  CVE refs); `codes` is `;`-separated (`CVE-2009-3699;OSVDB-58726`); one malformed code `CVE-cve : 2023-30367`.
  Header: `id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url`.
  Types: webapps, remote, dos, local, hardware.
- Metasploit: `https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json`
  (default branch `master`): 200, 11,442,316 bytes, ETag (SHA-256 of content), 304 on `If-None-Match`. One JSON
  object keyed `<type>_<ref_name>`; 7,274 modules (exploit 2,726, payload 2,651, auxiliary 1,377, post 436, …).
  Each has `fullname`, `type`, `references` (strings like `CVE-2024-3400`, `EDB-123`, `URL-…`; two CVE refs have a
  trailing space), `disclosure_date` (`YYYY-MM-DD` or null), `mod_time` (`2025-05-21 08:32:40 +0000`).
- Nuclei: `projectdiscovery/nuclei-templates`, branch `main`, MIT. 4,820 templates under `<protocol>/cves/<yyyy>/`
  (`http` 4,645, `network`, `javascript`, `code`, `headless`, `dast`, `cloud/kubernetes`, `websocket`).
  Raw: `…/main/http/cves/2024/CVE-2024-3400.yaml`: top-level `id`, `info { name, author, severity, description,
  reference, classification { cve-id, cwe-id, cvss-*, epss-*, cpe }, metadata, tags }`, then the request section.
- PoC-in-GitHub: `nomi-sec/PoC-in-GitHub`, branch `master`, CC0. One file per CVE at `<yyyy>/CVE-<id>.json`: a JSON
  array of GitHub repo objects (`id, name, full_name, owner{…}, html_url, description, fork, created_at,
  updated_at, pushed_at, stargazers_count, topics, …`). `2024/CVE-2024-3400.json` lists 45 repos (54 KB).

## What to build

Touch only: new `packages/parsers/src/{exploit-db,metasploit,nuclei,poc-in-github}.ts`, new tests in
`packages/parsers/test/`, new `fixtures/{exploit-db,metasploit,nuclei-templates,poc-in-github}/`, and the source
files `packages/sources/src/sources/{exploit-db,metasploit,nuclei-templates,poc-in-github}.ts`. No dependency
changes (there is no YAML or CSV library in `@ti/parsers`; don't add one), no change to `load.ts`, patterns, the
registry, the linker, apps, E2B, migrations, `DATA_LICENSES.md` or any other source. Never change a `licence`,
`credit` or `cadence`.

### 1. Shared rules

- Each module exports a named parser and `export const parse`, returning `ParseResult<SignalRecord>` (extra fields
  allowed, like `kev`'s `catalogVersion`). Worker-safe: no `node:` imports, `Buffer`, `fs` or `process`.
- Input forms: a `GitFile` (`text: null` or `status: 'removed'` → `{ records: [], unknownFields: [] }`), the raw
  text, or an already parsed value, as listed per parser. Anything else throws (the collector counts the item failed).
- `exploit-db.ts` exports the helpers the others import: `cveRefs(values: readonly string[]): string[]` (trim,
  keep `/^CVE-\d{4}-\d{4,}$/i`, `normaliseId`, unique, input order) and `isoDay(x: unknown): string | undefined`
  (the leading `YYYY-MM-DD` of a string, only if it is a real calendar date; otherwise `undefined`).
- One signal per (CVE, ref). A record with no valid CVE gives no signal. A record whose required date is
  missing or invalid is skipped and counted in `skipped: number` on the result.
- `ref` must match `/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,199}$/`; a record whose ref does not is skipped.
- Never copy `description`, `author`, `file`, `owner`, request sections, URLs other than the ones below, or any
  other free text into a record.

### 2. `exploit-db.ts` — `parseExploitDb(input): ParseResult<SignalRecord> & { skipped: number }`

Input: the whole CSV text (what the job passes), one row object (`Record<string, string>`), or an array of them.
Write a small RFC 4180 reader in the file: quoted fields, `""` escapes, commas and newlines inside quotes, LF or
CRLF, a trailing newline. The header must contain `id`, `date_published` and `codes`, else throw. Header names
outside the 17 known columns go to `unknownFields`. Per row: `id` must be digits; `cveRefs(codes.split(';'))`; for
each CVE: `{ vulnKey, kind: 'public_exploit', source: 'exploit-db', ref: 'EDB-<id>', firstSeen: isoDay(date_published),
evidenceDate: same, url: 'https://www.exploit-db.com/exploits/<id>' }`. `verified` 0 or 1 both count (an unverified
exploit is still public). `MAX_EDB_ROWS = 100_000`: more rows throws.

### 3. `metasploit.ts` — `parseMetasploit(input): ParseResult<SignalRecord> & { skipped: number }`

Input: the whole object (what the job passes), its JSON text, a `GitFile` of it, or one module object (has
`fullname`). Validate each module with Zod `looseObject` (`fullname`, `type`, `references: string[]`,
`disclosure_date: string | null`, `mod_time: string`). Kind by module:

| Module | Signal |
| ------ | ------ |
| `type: 'exploit'` | `public_exploit` |
| `type: 'auxiliary'`, `fullname` starts `auxiliary/scanner/` | `detection` |
| other `auxiliary` (admin, gather, dos, sqli, …) | `public_exploit` |
| `post`, `payload`, `encoder`, `nop`, `evasion` | none |

Per CVE in `cveRefs(references)`: `ref: fullname`, `firstSeen: isoDay(mod_time)` (the linker keeps the earliest,
so this is "seen by" until a module's add date is known), `evidenceDate: isoDay(disclosure_date)` when set, `url:
'https://github.com/rapid7/metasploit-framework/blob/master/modules/<fullname>.rb'`. Module keys outside the known
set go to `unknownFields` as their names. `MAX_MODULES = 50_000`.

### 4. `nuclei.ts` — `parseNucleiTemplate(input, today: Date): ParseResult<SignalRecord>`; `parse = (i) => parseNucleiTemplate(i, new Date())`

Input: a `GitFile` (its `path` builds the URL) or the YAML text. Read only the top of the template with a
line-based reader, not a YAML library: the top-level `id:` and the `info:` block (lines indented under it) up to
the next top-level key. From `info.classification.cve-id` accept a scalar (possibly quoted, possibly `a,b`
comma-separated), a flow list `[a, b]` or a block list (`- a`). Stop at the first top-level key after `info`; never
read the request section. Missing `id` throws; no CVE → no records. Per CVE: `{ kind: 'detection', source:
'nuclei-templates', ref: <id>, firstSeen: today as YYYY-MM-DD, url:
'https://github.com/projectdiscovery/nuclei-templates/blob/main/<path>' }` (no `url` without a path; no
`evidenceDate`: templates carry no date). Keys under `info` outside `name, author, severity, description, impact,
remediation, reference, classification, metadata, tags` go to `unknownFields` as `info.<key>`.

### 5. `poc-in-github.ts` — `parsePocInGithub(input): ParseResult<SignalRecord> & { skipped: number }`

Input: a `GitFile` only (the CVE comes from the file name; there is no CVE field). `path` must match
`/(?:^|\/)(CVE-\d{4}-\d{4,})\.json$/`, else no records. `text` is a JSON array. Per entry: skip `fork: true`;
require `full_name` matching `/^[\w.-]+\/[\w.-]+$/`, `html_url` equal to `https://github.com/<full_name>` and a valid
`created_at`, else skip and count. Sort kept entries by `created_at`, oldest first, and keep `MAX_POC_PER_CVE = 25`.
Each: `{ kind: 'poc', source: 'poc-in-github', ref: full_name, firstSeen: isoDay(created_at), evidenceDate: same,
url: html_url }`. Entry keys outside the known set (the fields listed under Endpoints plus `forks, forks_count,
watchers, watchers_count, score, subscribers_count, has_discussions, allow_forking, is_template, visibility,
web_commit_signoff_required, has_pull_requests, pull_request_creation_policy`) go to `unknownFields`.

### 6. Source config

| Source | Change |
| ------ | ------ |
| `exploit-db` | `parser: 'exploit-db'`; **also** `pattern: 'heavy'`, `heavy: true`; `pull: { heavy: { url: '<CSV URL above>' } }` |
| `metasploit` | `parser: 'metasploit'`; **also** `pattern: 'heavy'`, `heavy: true`; `pull: { heavy: { url: '<raw JSON URL above>' } }` |
| `nuclei-templates` | `parser: 'nuclei'`; `pull: { git: { repo: 'projectdiscovery/nuclei-templates', branch: 'main', include: ['**/cves/**/*.yaml'] } }` |
| `poc-in-github` | `parser: 'poc-in-github'`; `pull: { git: { repo: 'nomi-sec/PoC-in-GitHub', branch: 'master', include: ['*/CVE-*.json'] } }` |

Why the pattern changes: Exploit-DB lives on GitLab and the `git` pattern is GitHub only; Metasploit's index is
one 11 MB file, and a `git` first run would download the whole framework archive, exploit code included. Both are
over the 5 MB Worker limit anyway, so they go to E2B as `big-file` (the default `jobKind`) when the ETag changes.
Add a one-line comment in each of these two files saying so. Until the `big-file` job exists, an operator can load
them with a `first-load` job on `pull.heavy.url`.

Before committing, check each URL from the sandbox with `curl -sI` (the GitHub ones through
`https://api.github.com/repos/<repo>/commits/<branch>` with `Accept: application/vnd.github.sha`) and save the
status lines. If a host is unreachable from the sandbox, say so in the PR; don't guess.

### 7. Fixtures (each folder gets a `SOURCE.md`: URL, fetch date, licence, what was trimmed or hand-written)

- `fixtures/exploit-db/files_exploits.sample.csv`: the real header plus rows `16929` (one CVE + OSVDB), `1046` (two
  CVEs), `19049` (OSVDB only), `52705`, `52704`, `51637` (contains the malformed code), cut from the live file with
  `curl … | grep -E '^(id|16929|1046|19049|52705|52704|51637),'`, plus one hand-written row whose quoted description
  has a comma, a `""` and a newline, and one with `date_published` `2026-02-30`.
- `fixtures/metasploit/modules_metadata_base.sample.json`: eight real modules, `description` cut to 160 chars:
  `exploit_linux/http/panos_telemetry_cmd_exec` (CVE-2024-3400), `exploit_android/browser/webview_addjavascriptinterface`
  (two CVEs), `auxiliary_scanner/acpp/login`, `auxiliary_admin/2wire/xslt_password_reset`,
  `exploit_windows/fileformat/abbs_amp_lst` (trailing-space CVE), `exploit_android/adb/adb_server_exec` (no CVE),
  `post_android/local/koffee` (post + CVE), `payload_aix/ppc/shell_bind_tcp`. Add one unknown key to one module.
- `fixtures/nuclei-templates/CVE-2024-3400.yaml` (real); hand-written `multi-cve.yaml` (block-list `cve-id`, an
  unknown `info` key, a request section containing a `cve-id:` line that must be ignored) and `no-cve.yaml`.
- `fixtures/poc-in-github/CVE-2024-3400.json`: the real file trimmed to 3 entries, plus hand-written entries: one
  `fork: true`, one with `html_url` on another host, one with an unknown key.

### 8. Tests (`packages/parsers/test/exploits.test.ts`, `sources-exploits.test.ts`; Node, no network)

- Each fixture through its parser: exact signals (`vulnKey`, `kind`, `ref`, `firstSeen`, `evidenceDate`, `url`),
  `skipped` counts and `unknownFields`. Exploit-DB `1046` gives two signals; `19049` none; `51637` one
  (`CVE-2023-30367`); the bad date row is skipped. Metasploit: scanner → `detection`, admin → `public_exploit`,
  post and payload → none, trailing space trimmed. Nuclei with a fixed `today`; the request-section `cve-id` is
  ignored. PoC: fork, wrong host skipped; a synthetic file of 40 repos keeps the 25 oldest.
- Input forms agree: Exploit-DB whole text vs one row object; Metasploit object vs JSON text vs `GitFile` vs one
  module. `GitFile` removed / `text: null` → no records. A CSV without `codes` and a template without `id` throw.
- Grep the produced records: no field contains `description`, `author` or `file` values from the fixtures.
- `loadParser` resolves all four. `sources-exploits.test.ts`: `parser` and `pull` as in section 6; licences still
  `exploit-db: ask`, others `on`; `heavy` pattern `check()` for `exploit-db` with a stub `fetch` answering 304 to
  the stored ETag → `'unchanged'`; `git` `check()` for `nuclei-templates` with a stub answering 304 → `'unchanged'`.

## Not in scope

- `trickest-cve` (left unwired: its Markdown lists PoC-in-GitHub's repos plus many unrelated collections, a
  weaker and noisier signal; later), Exploit-DB shellcodes and papers, GitLab support in the `git` pattern.
- The `big-file` job itself, `first-load` from a git archive, deleting signals for removed files or repos, signal
  titles (`SignalRecord` has no title field), Metasploit module add dates, Nuclei templates outside `cves/`.

## Acceptance criteria

1. `pnpm build` (lint, typecheck, `pnpm test`) and `pnpm test:workers` pass; save both outputs.
2. The four parser files export the functions and constants named in sections 2–5; `parse` is exported by each.
3. The tests in section 8 pass on fixtures only; no test makes a network request.
4. `git diff --stat main -- packages/sources/src` shows only the four source files; the diff changes only
   `parser`, `pull` and, for `exploit-db` and `metasploit`, `pattern` and `heavy` (paste it in the PR).
5. `rg "from 'node:" packages/parsers/src` is empty; no new dependency; `pnpm-lock.yaml` unchanged.
6. Proof saved: the `curl` status lines for section 6, and a table of fixture → signals (count, kinds, vulnKeys).

## Decisions on the open questions

- Changing `pattern` to `heavy` and setting `heavy: true` on the Exploit-DB and Metasploit source files is
  accepted.
- Both set `pull.jobKind: 'first-load'`, so their hand-off runs the existing `first-load` job rather than the
  `big-file` stub.

## Changes from the first build of this branch

1. The `ref` character class allows `_` as well:
   `/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,199}$/` becomes `/^[A-Za-z0-9][A-Za-z0-9._:\/_-]{0,199}$/`. Metasploit
   module names, Nuclei ids and GitHub repository names contain underscores. Add a test for one.
2. Where section 6 and the decisions section disagree, the decisions section wins: Exploit-DB and Metasploit
   set `pull.jobKind: 'first-load'`.

Re-run every acceptance check.

## Changes from the second build of this branch

The parsers are done; the final `pnpm build` failed on two flaky tests that are already on main. Fix both here
(you may edit exactly these two test files and nothing else outside your area):

1. `test/parser-load-errors.test.ts` writes temporary parser modules (`tmp-throws.ts` and others) into
   `packages/parsers/src/` and deletes them, while other test files read that folder in parallel, so a
   parallel run can hit `ENOENT`. Make it deterministic without changing what it proves: for example write the
   temporary modules under a unique subfolder that no other test globs and point `loadParser` at it through
   the existing loader seam, or run that file alone (`describe.sequential` is not enough across files; use a
   unique folder). Run `pnpm test` five times in a row and show it passes each time.
2. `apps/web/test/worker.test.ts` matches the CSP nonce with `/'nonce-[\w-]+/`, but the nonce is base64 and can
   contain `+`, `/` and `=`, so it fails at random. Match `/'nonce-[A-Za-z0-9+/=_-]+'/` instead.

Re-run every acceptance check.
