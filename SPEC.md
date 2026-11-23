# contributor-path: docs that let an outsider add a source, proved by adding one

## Why

The repo is about to be public, and the most useful outside contribution is a new source. Today the guide for
that (`docs/adding-a-source.md`) and `CONTRIBUTING.md` were written before most of the code existed. They leave
out the `pull` block, how a parser receives its input, how tests drive a pattern without the network, and which
shared files and counts a new source changes. The README still says the code is a scaffold, and its quick start
runs a `pnpm deploy` script that does not exist.

This change rewrites those docs to match the code as it is, adds a one-page architecture overview, tightens the
issue templates, and then proves the path: it follows the guide to wire one real source that is in the registry
but unwired (`trickest-cve`), with a fixture and tests, and fixes every step of the guide that turned out wrong.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `docs/adding-a-source.md` | 7 steps. Says `registry.ts` is "the only shared file a new source touches"; but `packages/sources/src/registry.test.ts` and `test/sources-files.test.ts` pin the count (55) and the licence split (24/23/6/2), and `DATA_LICENSES.md` and `README.md` state the same numbers. Says nothing about `pull` (`PullConfig` in `packages/sources/src/pull.ts`), what `RawItem.body` each pattern hands the parser (`GitFile` for `git`), or the test helpers in `packages/patterns/test/helpers.ts` (`makeCtx`, `route`, `reply`, `SHA_A`). Step 7 says "list it in DATA_LICENSES.md", which has counts and the names of `wait`/`link` sources only, no per-source rows |
| `CONTRIBUTING.md` | Setup runs `pnpm lint && pnpm typecheck && pnpm test`; says Workers tests come "from M1". No mention of `pnpm build`, `pnpm test:workers`, the `*.workers.test.ts` naming, the rule that `pnpm build` stays laptop-light, or how PRs are reviewed |
| `README.md` | "Status: pre-alpha (milestone M0) … the code is a scaffold". Quick start ends in `pnpm deploy` (root scripts are `deploy:staging` / `deploy:production`, maintainer-only). Has a maintainers' "Before this repo goes public" checklist |
| `.github/ISSUE_TEMPLATE/` | `bug_report.yml`, `new_source.yml` (one free-text licence box), `config.yml` (security advisories link) |
| `docs/` | `IMPLEMENTATION_PLAN.md`, `adding-a-source.md`, `decisions/0001…0004`. No architecture overview |
| `CODE_OF_CONDUCT.md`, `SECURITY.md`, `DATA_LICENSES.md` | Exist; keep them |
| `trickest-cve` | `packages/sources/src/sources/trickest-cve.ts`: `git`, `daily`, licence `on`, no `parser`, no `pull`. No parser, no `fixtures/trickest-cve/` |
| Neighbours to copy | `poc-in-github` (source file, `packages/parsers/src/poc-in-github.ts`, `fixtures/poc-in-github/`), `nuclei` (injects `today` for `firstSeen`), tests in `packages/parsers/test/exploits.test.ts` and `sources-exploits.test.ts` |

Facts to keep in mind: `loadParser(name)` (`packages/parsers/src/load.ts`) imports `./<name>.ts`, so a parser
is found by file name with no map. `fixture(source, file)` (`test/fixtures.ts`) globs `fixtures/*/*`, one level
deep, so fixtures cannot sit in subfolders. Tests named `*.workers.test.ts` are excluded from `pnpm test` and run
by `pnpm test:workers` through each package's `vitest.workers.mts`. CI (`.github/workflows/ci.yml`) runs lint,
typecheck, `pnpm test` and `pnpm test:workers`.

## What to build

Do the sample source (section 1) first, writing down every place the current guide was wrong or silent, then
write the docs from that list. Every command, path, export name and count in the docs must be checked against
the code; don't describe anything the code does not do yet.

### 1. Sample source: `trickest-cve`

trickest/cve is a public GitHub repo with one Markdown file per CVE (`<yyyy>/CVE-<id>.md`), listing public
proof-of-concept links. It is a weak `poc` signal, like PoC-in-GitHub.

- **Licence check first.** `curl` the repo's licence (`https://api.github.com/repos/trickest/cve` → `license`,
  and the raw `LICENSE` file if there is one). Record what you find in `fixtures/trickest-cve/SOURCE.md`. The
  registry status is `on`; if the licence is missing or forbids commercial use, stop, don't wire the source and
  don't change its status, and say so in the PR. Never change a licence status in this PR.
- **Fixture** `fixtures/trickest-cve/`:
  - `CVE-2024-3400.md`: the real file from
    `https://raw.githubusercontent.com/trickest/cve/main/2024/CVE-2024-3400.md`, trimmed to at most 5 GitHub
    links. If curl cannot reach it, hand-write a realistic file and say so in `SOURCE.md` and the PR.
  - `edge-cases.md` (hand-written): a link repeated twice, a link with a deep path (`/tree/main/x`), a non-GitHub
    link under the GitHub heading, a Reference section with only non-GitHub links, and an unknown `###` heading.
  - `SOURCE.md`: URL, fetch date, licence, what was trimmed, which file is hand-written.
- **Parser** `packages/parsers/src/trickest-cve.ts`, Worker-safe, no Node imports:
  - `parseTrickestCve(input: unknown, today: Date): ParseResult<SignalRecord> & { skipped: number }` and
    `export const parse = (input: unknown) => parseTrickestCve(input, new Date())`.
  - Input is a `GitFile` (`packages/patterns/src/git.ts`); throw `trickest-cve: input must be a GitFile` for
    anything else. `status: 'removed'` or `text: null` → no records. A path not matching
    `(?:^|/)(CVE-\d{4}-\d{4,})\.md$` → no records. The CVE comes from the path, through `normaliseId`.
  - Read only the list items under the `#### Github` heading (match the heading case-insensitively; the section
    ends at the next heading). Keep a line only if it is exactly `- https://github.com/<owner>/<repo>` with an
    optional trailing `/`, and `<owner>/<repo>` passes the same `FULL_NAME` and `SAFE_REF` checks as
    `poc-in-github`. Anything else under that heading counts as `skipped`. Ignore every other section; never
    copy the description text. Check the real file: if its layout differs from this, follow the real file and
    say what differed in the PR.
  - De-duplicate within the file, keep file order, cap at `MAX_POC_PER_CVE` (import it from `./poc-in-github`).
  - Each record: `{ vulnKey, kind: 'poc', source: 'trickest-cve', ref: '<owner>/<repo>', firstSeen: <today as
    yyyy-mm-dd>, url: 'https://github.com/<owner>/<repo>' }`.
  - `unknownFields`: `heading:<text>` for each `###`/`####` heading not in Description, POC, Reference, Github
    (and whatever other headings the real file has, once checked).
- **Source file** `packages/sources/src/sources/trickest-cve.ts`: add
  `parser: 'trickest-cve'` and `pull: { git: { repo: 'trickest/cve', branch: 'main', include: ['*/CVE-*.md'] } }`
  (confirm the default branch with the API call above). Keep id, name, gives, pattern, cadence, licence and the
  default credit. `registry.ts` is not touched: the source is already listed.
- **Tests** `packages/parsers/test/trickest-cve.test.ts` (Node, part of `pnpm test`):
  - the real fixture gives the expected records, exactly (`toEqual`), with a fixed `today`;
  - each edge case: duplicate kept once, deep path / non-GitHub skipped and counted, Reference-only links give
    nothing, unknown heading reported, `removed` and `text: null` give nothing, a non-matching path gives
    nothing, a non-`GitFile` throws;
  - more than `MAX_POC_PER_CVE` links are cut to the cap;
  - `loadParser('trickest-cve')` resolves and its `parse` returns records for the fixture;
  - the registry entry matches the `parser` and `pull` above and keeps `licence: 'on'`, `cadence: 'daily'`;
  - the git "unchanged" path: with a `commit` cursor and a `304` from
    `https://api.github.com/repos/trickest/cve/commits/main`, `check()` returns `'unchanged'` (copy the
    `git check: a 304 is unchanged` test in `sources-exploits.test.ts`).
  - No test touches the network.

### 2. `docs/adding-a-source.md` (rewrite)

A numbered walk-through that an outsider can follow top to bottom, using `trickest-cve` as the worked example
with real snippets from section 1. It must cover, each checked against the code:

1. Licence: the four statuses and what the code does with each (`packages/core/src/licence.ts`); how to find and
   record the terms; that maintainers, not contributors, decide `wait` vs `ask`; exploits are metadata only.
2. Picking a pattern: the existing table, plus a one-line note per pattern on what its `pull` block needs
   (from `PullConfig`) and what `RawItem.body` the parser receives (read each `packages/patterns/src/<p>.ts`).
3. The source file: `src(id, name, gives, pattern, cadence, licence, extra)` from `define.ts`, `credit`,
   `parser`, `pull`, `heavy`/`jobKind`; file name equals id.
4. Brand-new source vs wiring an existing entry: a brand-new one also adds an import and an entry in
   `registry.ts`, and updates the counts in `registry.test.ts`, `test/sources-files.test.ts`,
   `DATA_LICENSES.md` and `README.md`. Say exactly which numbers.
5. The parser: `packages/parsers/src/<name>.ts` exporting `parse(input)`, found by `loadParser`; return
   `{ records, unknownFields }`; Worker-safe; inject the clock if it uses today's date; tests live in
   `packages/parsers/test/`.
6. The fixture: one level under `fixtures/<id>/`, trimmed real data, `SOURCE.md` fields, hand-written cases
   marked as such, no personal data.
7. Tests: parser on the fixture, wiring, and the pattern's unchanged path with `makeCtx`/`route`/`reply`; when a
   test needs workerd, name it `*.workers.test.ts`.
8. `DATA_LICENSES.md`: what to change (counts, `wait`/`link` names, special notes), not per-source rows.
9. Run `pnpm build`, then `pnpm test:workers` if you touched Workers code; open the PR with the template.

Keep it under about 200 lines. Link the plan's §4 for detail instead of copying it.

### 3. `CONTRIBUTING.md` (rewrite)

Sections: setting up (Node 22, pnpm 10, `pnpm install --frozen-lockfile`, no Cloudflare account needed);
**the laptop-light rule** (`pnpm build` = Biome + `tsc` + Node unit tests, no workerd, no servers, no network;
anything needing the Workers runtime is a `*.workers.test.ts` run by `pnpm test:workers` and by CI on every PR);
ground rules (keep the current six, corrected); adding a source (short, pointing to the guide); how PRs are
reviewed (CI must be green; a maintainer reviews against `REVIEW.md`, which lists what blocks a merge: licence
gates, secrets, budgets, migrations, personal data; changes to workflows, `wrangler.jsonc`, migrations and auth
or webhook code get an extra maintainer look; one source per PR); licence rules for sources; ADRs for design
changes; commit messages; code of conduct and `SECURITY.md` pointers; the Apache-2.0 line.

### 4. `docs/architecture.md` (new)

One page, under about 150 lines: the apps and packages and what each owns, then **one** Mermaid `flowchart`
of the data flow: cron → collector planner → queue → step (pattern `check`/`fetch` → parser → linker → D1,
receipts → R2 `raw/`) → heavy hand-off through the API's signed `/internal/jobs` routes → E2B job → R2 → loader
→ D1; changes → notify → email; web → API → D1 and R2 search shards. Draw only arrows the code has: read the
cron strings and bindings in each `apps/*/wrangler.jsonc` and the entry files before drawing. Link the plan and
the ADRs. No status claims about unfinished work, no account ids, hostnames or URLs of any deployment.

### 5. `README.md`

Replace the status line with one that is true today (no milestone number). Rewrite the quick start for a
contributor: install, `pnpm build`, `pnpm test:workers`; then "running your own copy" in two or three sentences:
bring your own Cloudflare (and optional E2B, Clerk, Resend) accounts, copy `apps/api/.dev.vars.example`, fill
the `${VAR}` placeholders through `.env` (`scripts/wrangler-config.mjs`), and see the plan §2 and §13. Remove
`pnpm deploy`. Link `docs/architecture.md` and `docs/adding-a-source.md`. Leave the maintainers' checklist and
the licence section as they are.

### 6. Issue templates

- `new_source.yml`: keep the current fields; add a required dropdown "Can the data be used commercially?"
  (yes, with attribution / no or needs permission / no terms found / not sure), a terms URL input, the
  attribution text the source asks for, a dropdown for the likely pattern, and a required checkbox "I am not
  asking to fetch or store exploit code".
- `bug_report.yml`: add an area dropdown (data on an entry page, search, API, alerts/email, collector or
  pipeline, docs, other) and a note not to paste API keys, tokens or personal data.
- Both must stay valid GitHub issue-form YAML (unique ids, required `name`/`description`/`body`).

## Not in scope

- `.github/pull_request_template.md`, `.github/workflows/**`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  `DATA_LICENSES.md` (the sample source changes no count), `docs/IMPLEMENTATION_PLAN.md`, `docs/decisions/**`.
- Any change to `apps/**`, `e2b/**`, `packages/patterns/**`, `packages/core/**`, other sources or parsers.
- Unpacking the repository archive the `git` pattern hands off on a source's first run; the first-load job owns
  that. This PR wires steady-state pulls only and says so in the source file comment.
- A docs site, translations, screenshots.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process; `pnpm test:workers` passes. Save both outputs.
2. `git diff --name-only main` lists only `docs/adding-a-source.md`, `docs/architecture.md`, `CONTRIBUTING.md`,
   `README.md`, `.github/ISSUE_TEMPLATE/*.yml`, `packages/sources/src/sources/trickest-cve.ts`,
   `packages/parsers/src/trickest-cve.ts`, `packages/parsers/test/trickest-cve.test.ts` and
   `fixtures/trickest-cve/*`.
3. The tests in section 1 exist and pass; `rg -n "fetch\(|https?://" packages/parsers/test/trickest-cve.test.ts`
   shows URLs only as route keys or expected values, never a real request.
4. `fixtures/trickest-cve/SOURCE.md` names the URL, fetch date and licence found, and says whether the real file
   was fetched. The PR states the licence check result.
5. A walk-through log saved as proof: each step of the new `docs/adding-a-source.md`, the command or file it led
   to, and whether the old guide was wrong or silent there. Every "wrong" item is fixed in the new guide.
6. Every command in `README.md`, `CONTRIBUTING.md` and `docs/adding-a-source.md` exists (root or package
   `scripts`, or a real binary); every repo path they name exists. Save the check (a short script or listing).
7. `docs/architecture.md` has exactly one Mermaid block, and each arrow is backed by a file you name in the PR.
8. Both issue templates parse as YAML and have unique field ids. The repo has no YAML package; use a throwaway
   one (`npx --yes yaml@2 valid < file`, or Python's PyYAML), never a new dependency. Save the output.
9. `rg -n -i "account_id|[0-9a-f]{32}|@[a-z0-9-]+\.(com|io|dev)|workers\.dev" docs CONTRIBUTING.md README.md
   .github/ISSUE_TEMPLATE` finds no account ids, deployment hostnames or personal emails (placeholders like
   `<branch>` are fine). Save the output.

## Decisions on the open questions

- You may also edit `DATA_LICENSES.md` (add a per-source table generated from the registry, so the guide's
  "list it there" step works) and `.github/pull_request_template.md`.
- Wiring steady-state pulls only for the sample source is fine; first loads from repository archives are being
  fixed separately.
