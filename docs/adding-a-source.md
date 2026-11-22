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
3. **Add a registry entry** in `packages/sources/src/registry.ts`.
4. **Write or reuse a parser** in `packages/parsers`. It returns typed records and an `unknownFields` list.
5. **Record a fixture** in `fixtures/<source-id>/`: one small, trimmed real response, plus `SOURCE.md` (URL, date, licence).
6. **Test** the parser on the fixture and the pattern's "unchanged" path.
7. **List it** in `DATA_LICENSES.md`.
