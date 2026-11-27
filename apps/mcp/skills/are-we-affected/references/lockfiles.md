# Lockfile formats

One row per format: the ecosystem to send, where the package name and the exact version are, and which entries to skip.

Keep entries marked as dev-only. They are still present on developer machines and in CI. Skip workspace packages, local packages and packages that come from a git URL or a local path, and list them as "not checked".

Take the name and the version only. Never copy a URL, a hash or a path.

| File | Ecosystem | Name and version | Skip |
| ---- | --------- | ---------------- | ---- |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | Each key under `packages` after the last `node_modules/` gives the name. `version` is next to it. If the entry has a `name` field (an alias), the real package is that `name`: always use `name` when present, never the key. Older files list names and versions under `dependencies`. | The root entry (empty key), `link: true` entries, entries whose `resolved` is a git URL or a file path |
| `pnpm-lock.yaml` | npm | Keys under `packages` read `name@version` (older files use `/name/version`). A scoped name starts with `@`. | Keys with a `file:`, `link:` or git source. Drop any peer suffix in parentheses. |
| `yarn.lock` | npm | Classic: a header like `name@range:` and a `version` line below it. Berry: the same, with a `resolution` line of `name@npm:version`. | Entries whose resolution uses `workspace:`, `file:`, `link:`, `patch:` or git |
| `bun.lock` | npm | Entries under `packages` hold `name@version` as the first item of each array. | Entries with `workspace:`, `file:`, `link:` or git sources |
| `requirements*.txt` | PyPI | Lines of the form `name==version`. Also read pip-compile output: a `name==version` line that continues onto `--hash` lines counts. Strip extras (`name[extra]` becomes `name`) and environment markers (everything from `;`). | Every other line: ranges, flags, `-r` includes, URLs, editable entries, comments |
| `poetry.lock` | PyPI | Each `[[package]]` block has `name` and `version`. | Blocks whose source type is `git`, `directory` or `file` |
| `uv.lock` | PyPI | Each `[[package]]` block has `name` and `version`. | Blocks whose source is `git`, `path`, `directory` or `editable`, and the project's own entry |
| `Pipfile.lock` | PyPI | Keys under `default` and `develop`. `version` reads `==x.y.z`; take the part after `==`. | Entries with `git`, `path` or `file` keys, or without a pinned version |
| `pdm.lock` | PyPI | Each `[[package]]` block has `name` and `version`. | Blocks with `git`, `path` or `editable` sources |
| `go.sum` | Go | Each line is `module version hash`. The module path is the name. A module path is a name, not a URL. | Lines whose version ends in `/go.mod`, and duplicates of the same module and version |
| `Cargo.lock` | crates.io | Each `[[package]]` block has `name` and `version`. | Blocks with no `source`, and blocks whose `source` is a git URL or a path |
| `Gemfile.lock` | RubyGems | Under `GEM`, specs read `name (version)`. | Everything under `GIT` and `PATH` |
| `composer.lock` | Packagist | Entries in `packages` and `packages-dev` have `name` and `version`. Send the version as written; MTI handles a leading `v`. | Entries whose `dist` or `source` is a path |
| `packages.lock.json` | NuGet | Under each target framework, each key is the name and `resolved` is the version. | Entries of type `Project` |
| `gradle.lockfile` | Maven | Each line reads `group:artifact:version=configurations`. The name is `group:artifact`. | Comment lines and the `empty=` line |
| `mix.lock` | Hex | Each entry reads `"name": {:hex, :name, "version", ...}`. | Entries that are `:git` |
| `pubspec.lock` | Pub | Under `packages`, each key is the name and `version` is below it. | Entries whose `source` is `git`, `path` or `sdk` |
| `Package.resolved` | SwiftURL | Each pin has a `location` and a `state.version`. The name is the host and path of the `location`, without the scheme, credentials or a trailing `.git`. | Pins that have a `branch` or `revision` but no `version`, and local paths |
| `*.cdx.json`, `bom.json` (CycloneDX) | From the purl type | Each component has a `purl`, or a `name` and a `version`. Read the type, name and version from the purl, then drop the rest of the purl, including every qualifier. | Components with no version, and files, applications and operating-system components |
| `*.spdx.json`, `sbom*.json` (SPDX) | From the purl type | In `externalRefs`, find the reference of type `purl`. Read the type, name and version from it and drop the rest. | Packages with no purl or no version |

## Ecosystem names

Send the ecosystem as one of these exact names: npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, SwiftURL, GitHub Actions, Debian, Ubuntu, Alpine, Red Hat. Any other value is refused.

For purls, map the purl type like this. Any other type is "not checked".

| Purl type | Ecosystem |
| --- | --- |
| `npm` | npm |
| `pypi` | PyPI |
| `golang` | Go |
| `maven` | Maven |
| `cargo` | crates.io |
| `gem` | RubyGems |
| `nuget` | NuGet |
| `composer` | Packagist |
| `hex` | Hex |
| `pub` | Pub |
| `swift` | SwiftURL |
| `github` | GitHub Actions |

For a purl, percent-decode the namespace and the name, then join them with `/`. Examples are npm `@scope/name`, Go and Swift paths, and Packagist `vendor/name`. Maven is the exception: it is `group:artifact`.

## Notes

- A lockfile can list one package at several versions. Check each version.
- Do not send the same ecosystem, name and version twice.
- Skip any field that is not a plain name or a plain version.
