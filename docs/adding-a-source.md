# Adding a source

A walk-through, top to bottom. The worked example is `trickest-cve`, a real source wired by following this
guide: [`packages/sources/src/sources/trickest-cve.ts`](../packages/sources/src/sources/trickest-cve.ts),
[`packages/parsers/src/trickest-cve.ts`](../packages/parsers/src/trickest-cve.ts), its
[fixtures](../fixtures/trickest-cve/) and
[tests](../packages/parsers/test/trickest-cve.test.ts). For the design behind patterns and parsers, see
[the plan, section 4](IMPLEMENTATION_PLAN.md#4-shared-packages). For the big picture, see
[architecture.md](architecture.md).

## 1. Check the licence

Read the source's terms before writing code. The registry records one status per source
(`LicenceStatus` in `packages/core/src/licence.ts`):

| Status | Meaning                                             | What the code does                                             |
| ------ | --------------------------------------------------- | -------------------------------------------------------------- |
| `on`   | Commercial use allowed, with attribution            | Ingested and shown in full, with the credit line               |
| `ask`  | No written terms found                              | Ingested and shown with credit; confirmation is being sought   |
| `wait` | Needs written permission, or forbids commercial use | Not ingested (`canIngest`) and hidden (`displayMode`)          |
| `link` | All rights reserved                                 | Ingested, but only ID, title, date and link are kept and shown |

Find the terms: a `LICENSE` file, the repository's licence on GitHub (`curl https://api.github.com/repos/<owner>/<repo>`
shows `license`), or the site's terms page. Write down the URL and what it says in the fixture's `SOURCE.md`
(step 6) and in your PR. For `trickest/cve` that is MIT.

You propose a status; maintainers decide. In particular, only a maintainer moves a source between `wait` and
`ask`. If the terms forbid commercial use or are unclear, say so and ship it as `wait`. Exploit sources are
metadata only: ID, date, URL and CVE. Never fetch or store exploit code.

## 2. Pick a pattern

How does the source tell you what changed? Each pattern reads its own block of the source's `pull` config
(`PullConfig` in `packages/sources/src/pull.ts`) and hands the parser one `RawItem.body` per item.

| The source has…                         | Pattern       | `pull` block needs                                                       | The parser receives (`RawItem.body`)                                                |
| --------------------------------------- | ------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| a git repo (GitHub)                     | `git`         | `git: { repo: 'owner/name', branch?, include: [globs] }`                 | a `GitFile`: `{ path, status, previousPath?, text }`; `text` is `null` when removed |
| its own list of changed records         | `changelist`  | `changelist: { listUrl, timeColumn, refColumn, itemUrl }`                | `{ ref, time, text }`; `text` is `null` if the item is gone                         |
| an API with a "modified since" filter   | `since`       | `since: { url, startParam, offsetParam, limitParam, itemsPath, idPath }` | the response document with its items array cut to one entry                         |
| one small file with an ETag or version  | `fingerprint` | `fingerprint: { url, format, key }`                                      | one changed entry (with `itemsPath`, the whole document cut to that entry)          |
| an RSS or Atom feed                     | `feed`        | `feed: { url }`                                                          | one feed item as parsed XML; for `link` sources only `{ id, title, date, link }`    |
| only a web page                         | `page`        | `page: { url, item, key, fields }`                                       | one row: an object with a value per configured field                                |
| a big file, or data that changes rarely | `heavy` (E2B) | `heavy: { url }`, optional `version`                                     | none: a job parses the file in E2B, not a Worker                                    |

Git sources only request data files (`json`, `csv`, `md`, `xml`, `yaml`, `yml`, `txt`), never code. Read
`packages/patterns/src/<pattern>.ts` for the exact shapes. One call returns at most 40 items.

## 3. Write the source file

Create `packages/sources/src/sources/<id>.ts`. The file name must equal the `id`. It default-exports the
result of `src(id, name, gives, pattern, cadence, licence, extra)` from `define.ts`:

```ts
export default src(
  'trickest-cve',
  'trickest/cve',
  'Proof-of-concept links (weak signal)',
  'git',
  'daily',
  'on',
  {
    parser: 'trickest-cve',
    pull: { git: { repo: 'trickest/cve', branch: 'main', include: ['*/CVE-*.md'] } },
  },
);
```

`extra` takes optional fields: `credit` (default `Source: <name>`), `parser` (the parser file name, step 5),
`pull` (step 2), `heavy` (hand big files to E2B) with `jobKind` inside `pull`, plus `urls` and `rateLimit`.
`cadence` is one of `3h`, `daily`, `weekly`, `monthly`, `quarterly`, `with-cve-list`.

The `git` pattern pulls what changed since the last commit it saw. On a source's first run it hands the whole
repository archive to the first-load job, which owns unpacking it; a source file only configures the steady
state.

When the collector runs a source:

- On the 3-hourly tick, a source that has a `pull` block, whose ingest is allowed and that has never had a
  successful run is due at once, whatever its `cadence`. After that first success its `cadence` applies. Never-run
  heavy sources (`heavy`, the `heavy` pattern, `git`) start at most `FIRST_RUN_HEAVY_PER_TICK` (2) per tick, so a
  new environment stays under the E2B job limit and fills within a day.
- A source with no `pull` is recorded as `skipped` on its cadence: `link only: not ingested` for `link` sources,
  `read from CVE List records` for `cisa-vulnrichment`, otherwise `source has no pull config yet`.
- A source on `sec.gov` is sent `Motiontic Threat Index <contact>`, the contact being `CONTACT_EMAIL`
  (`TI_CONTACT_EMAIL`) or the address inside `USER_AGENT`. With no contact it is skipped, not sent.
- A run that reaches `MAX_STEPS_PER_RUN` ends `ok` with a note, keeps its cursor and carries on next tick.

## 4. New source, or wiring an existing entry?

If the id is already listed in `packages/sources/src/registry.ts`, you only fill in its file (`parser`, `pull`)
and nothing else is shared. `trickest-cve` was like this.

A brand-new source also needs:

- an import and an entry in `packages/sources/src/registry.ts`;
- the source count in `packages/sources/src/registry.test.ts` (every `55`, the test name and the two checks) and
  `test/sources-files.test.ts` (the same);
- the licence split in `registry.test.ts` (24 `on`, 23 `ask`, 6 `wait`, 2 `link`), and the same numbers in
  `DATA_LICENSES.md`;
- the numbers in `README.md` ("55 public sources", "The 55-source registry", and the "Eight sources ship
  switched off" line, which is `wait` plus `link`).

## 5. The parser

A parser is one file, `packages/parsers/src/<name>.ts`, that exports `parse(input)`. `loadParser` finds it by
file name, so there is no map to edit; the file name is what you put in `parser:`. `parse` returns
`{ records, unknownFields }` (a `ParseResult`); list any field or heading you did not expect in
`unknownFields`. A parser must be Worker-safe: no `node:` imports, no `Buffer`, no `process`. If it uses
today's date, take the clock as an argument and wrap it, as `trickest-cve` does:

```ts
export function parseTrickestCve(
  input: unknown,
  today: Date,
): ParseResult<SignalRecord> & { skipped: number } {
  /* … */
}
export const parse = (input: unknown) => parseTrickestCve(input, new Date());
```

Import other packages by subpath (`@ti/core/ids`); a bare `@ti/core` import fails. Parser tests live in
`packages/parsers/test/`, never in `src/`, because the bundler includes everything in `src/`. Copy a
neighbour for the record shape: `poc-in-github` or `nuclei`.

## 6. The fixture

Save real data under `fixtures/<id>/<file>`, one level deep (`fixture()` globs `fixtures/*/*`, so
sub-folders are not found). Trim it to what a test needs. Add `fixtures/<id>/SOURCE.md` with the URL, the fetch
date, the licence, what you trimmed, and which files you wrote by hand. Mark every hand-written case as such.
Keep personal data out; use invented names.

## 7. Tests

In `packages/parsers/test/<name>.test.ts`, using `fixture(source, file)` from `test/fixtures.ts`:

- the parser on the real fixture, with `toEqual` on the records;
- each edge case (duplicates, bad input, empty input, removed items, a cap);
- the wiring: `loadParser('<name>')` resolves, and the registry entry has the `parser` and `pull` you set;
- the pattern's "unchanged" path, with helpers from `packages/patterns/test/helpers.ts`:

```ts
const h = makeCtx({
  source,
  cursor: { kind: 'commit', value: SHA_A },
  routes: [route('https://api.github.com/repos/trickest/cve/commits/main', reply(null, 304))],
});
expect(await gitCheck(h.ctx)).toBe('unchanged');
```

`makeCtx` serves only the `routes` you give it and fails any other request, so no test touches the network.
If a test needs the Workers runtime, name it `*.workers.test.ts`: `pnpm test` skips it and `pnpm test:workers`
(and CI) runs it.

## 8. Update `DATA_LICENSES.md`

It has the per-status counts, the names of the `wait` and `link` sources, special notes, and a table of every
source with its status. Update the table row for your source and, for a new source, the counts and names.

## 9. Check and open the PR

```bash
pnpm install --frozen-lockfile
pnpm build           # Biome, tsc and the Node unit tests
pnpm test:workers    # only if you touched Workers code
```

Open the PR with the template. One source per PR. See [CONTRIBUTING.md](../CONTRIBUTING.md) for how it is
reviewed.
