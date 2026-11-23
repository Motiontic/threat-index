# Adding a source

This expands step by step on CONTRIBUTING.md.

1. **Read the source's terms.** Pick its licence status:
   - `on`: commercial use allowed with attribution;
   - `ask`: no written terms;
   - `wait`: needs written permission or forbids commercial use;
   - `link`: all rights reserved.
2. **Pick a pattern.** How does the source tell you what changed?

   | The source has…                                               | Pattern       |
   | ------------------------------------------------------------- | ------------- |
   | a git repo                                                    | `git`         |
   | its own list of changed records                               | `changelist`  |
   | an API with a "modified since" filter                         | `since`       |
   | one small file with an ETag or version number                 | `fingerprint` |
   | an RSS or Atom feed                                           | `feed`        |
   | only a web page                                               | `page`        |
   | a big file (over about 1 MB) or something that changes rarely | `heavy` (E2B) |
3. **Add a source file** `packages/sources/src/sources/<id>.ts`. It default-exports the source's config; copy a
   neighbour. The file name must equal the `id`. Then add one import and one array entry in
   `packages/sources/src/registry.ts` (the only shared file a new source touches; an existing source
   never needs it). Optional fields `urls`, `parser` and `rateLimit` belong in the source file.
4. **Write or reuse a parser.** Each parser is one file `packages/parsers/src/<format>.ts` that exports
   `parse(input)`. Name it in the source file with `parser: '<format>'`; the collector finds it by that
   name (`loadParser` in `packages/parsers/src/load.ts`), so no map needs editing. A parser returns
   typed records and an `unknownFields` list. Keep parser tests in `packages/parsers/test/`, not in
   `src/`, because the bundler includes everything in `src/`.
5. **Record a fixture** in `fixtures/<source-id>/`: one small, trimmed real response, plus `SOURCE.md`
   (URL, date, licence). Tests read it with `fixture(source, file)` from `test/fixtures.ts`, which works
   in both kinds of test.
6. **Test** the parser on the fixture and the pattern's "unchanged" path. `pnpm test` runs Node-only
   unit tests (part of `pnpm build`). `pnpm test:workers` runs tests that need the Workers runtime, with
   local D1, R2, KV and Queues; it runs in loop sandboxes and CI.
7. **List it** in `DATA_LICENSES.md`.

Import other packages by subpath, for example `@ti/core/licence`. A bare `@ti/core` import fails
`pnpm test`.
