# version-match: correct "is this version affected?" answers for every MTI ecosystem

## Why

The package check asks one question many times: is version X of a package inside an advisory's affected
range? The `affected` table stores each range as OSV events (`introduced`, `fixed`, `last_affected`). To
answer, you need the ecosystem's own version order. Plain string order is wrong almost everywhere:

- semver: `1.10.0 > 1.9.0`
- Maven: `1.0-SNAPSHOT < 1.0 < 1.0-sp`
- PyPI: `1.0rc1 < 1.0 < 1.0.post1`
- Debian: `1.0~rc1 < 1.0`, and `1:0.9 > 2.0` because of the epoch

mcp-seams added the contract (`Comparer`, `comparerFor`, `inRange`) and the OSV range walk, but no
comparers. So every ranged row answers `'unsupported'` today. This change adds a comparer for each of the
16 ecosystems in `ECOSYSTEMS`. Each one is tested against published test vectors, is safe on untrusted
input, and is fast enough for a 1,000-package check.

It also lets "every version" rows match with no comparer at all. Every malicious-package record has that
shape.

## Current state (on main after mcp-seams)

| Area | Today |
| ---- | ----- |
| `packages/core/src/versions/index.ts` | `Comparer { valid(v): boolean; compare(a, b): number }`. `comparerFor(ecosystem)` returns `null` for every ecosystem. `RangeRow { range_type, introduced, fixed, last_affected, versions }`. `inRange`: `EXACT` rows match by string equality; other rows run the OSV walk with the comparer, or return `'unsupported'` when there is none. Tests: the walk with a toy integer comparer, and "every ecosystem returns `'unsupported'`" |
| `packages/core/src/packages.ts` | `ECOSYSTEMS`: `npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, SwiftURL, GitHub Actions, Debian, Ubuntu, Alpine, Red Hat`, plus `type Ecosystem`. Not touched here |
| `affected` (advisories `0002`) | One row per range. `range_type` is `SEMVER`, `ECOSYSTEM` or `EXACT`. `introduced` is `NOT NULL DEFAULT '0'`, so `EXACT` rows also carry `'0'`. No `limit` column. Nothing writes rows yet |
| Version strings in the data | Checked in `fixtures/`. Go: `SEMVER`, no `v` (`0.52.0`), while `go.mod` users send `v0.51.0`. npm malicious package: `SEMVER`, `introduced: '0'` and nothing else. GHSA npm: `ECOSYSTEM`. Debian: `1:1.43.12+dfsg-1~deb13u1`. Ubuntu: `3.0.2-7ubuntu2.14`, `4.15.0-1023.24~14.04.1`. GHSA GitHub Actions (`tj-actions/changed-files`): `ECOSYSTEM`, `fixed: 46.0.1` |
| `packages/core/package.json` | `exports: { "./*": "./src/*.ts" }`; one dependency (`zod`); no dev dependencies. Not touched here |
| Unit tests | Root `vitest.config.ts` runs every `*.test.ts` except `*.workers.test.ts`, inside `pnpm build`. Core's tests sit next to the code (`src/*.test.ts`) |
| Workers tests | `vitest.workers.config.mts` loads every `apps/*/vitest.workers.mts` and `packages/*/vitest.workers.mts`. `packages/core` has none. `packages/patterns/vitest.workers.mts` is a project with no bindings (compatibility date `2026-11-01`, `nodejs_compat`). CI runs `pnpm test` and `pnpm test:workers` |
| Raw files in tests | `(import.meta as unknown as GlobImportMeta).glob(pattern, { query: '?raw', import: 'default', eager: true })`, as in `packages/linker/src/schema.test.ts`. Works in Node and in workerd |
| Fixtures | `test/fixtures.ts` inlines every file matching `fixtures/*/*` (one level deep) into any test that imports it. Each fixture folder has a `SOURCE.md`. Biome ignores `fixtures/` |
| Lint | Biome 2 recommended preset, 110 columns, single quotes. `test/no-barrel-imports.test.ts` forbids `packages/*/src/index.ts` and bare `@ti/<pkg>` imports. A nested `src/versions/index.ts` is fine |
| NOTICE | This repo's Apache-2.0 notice. Says the repo holds no third-party vulnerability data |
| Workers clock | Deployed, `performance.now()` only moves after I/O. In local workerd it also moves during CPU work ([docs](https://developers.cloudflare.com/workers/runtime-apis/performance/)) |

This change needs mcp-seams on main. If `src/versions/index.ts` (with the exports above and their tests) or
`ECOSYSTEMS` is missing, stop and say so.

## What to build

You may touch only these paths:

- `packages/core/src/versions/**` (code and tests);
- `packages/core/vitest.workers.mts` (new: this package's Workers test project);
- `fixtures/versions/**` (new).

Leave `packages/core/src/packages.ts`, `packages/core/package.json`, `pnpm-lock.yaml`, NOTICE and
everything else alone. Add no dependencies: this is pure TypeScript. The signatures of `Comparer`,
`comparerFor`, `RangeRow` and `inRange` don't change, because other features already code against them.

### 1. Shared rules (`common.ts`)

```ts
export const MAX_VERSION_LENGTH = 128;
/** 1–128 characters, each printable ASCII (0x21–0x7E). Checks typeof and length first, so a huge input costs O(1). */
export function isSafeVersion(v: unknown): v is string;
/** Two runs of ASCII digits compared as whole numbers of any size: skip leading zeros, then the longer run
 *  is larger, then code-unit order. */
export function compareDigits(a: string, b: string): -1 | 0 | 1;
/** Order for strings a comparer can't parse: invalid sorts below every valid version; two invalid strings
 *  compare by code-unit order. */
export function compareInvalid(a: string, aValid: boolean, b: string, bValid: boolean): -1 | 0 | 1;
```

Every comparer follows these rules:

- **`valid(v)`** is `isSafeVersion(v)` plus the ecosystem's grammar. It never throws, for any input, including
  non-strings. So it rejects absurd input: empty, over 128 characters, control characters, whitespace and
  non-ASCII characters (`１.２.３`, `‮`).
- **`compare(a, b)`** returns exactly `-1`, `0` or `1` and never throws. `compare(a, a)` is `0`.
  `compare(a, b)` equals `-compare(b, a)`. The order is transitive over valid versions.
- **Invalid input.** If either side is invalid, use the ecosystem's own rule for invalid strings when its
  vectors define one (Alpine, PyPI legacy versions; see section 2). Otherwise use `compareInvalid`.
- **Hand-written scanners over character codes.** Use no regular expressions at all: no literals and no
  `RegExp` (a test enforces this). Don't use `localeCompare` or `Intl`. Lower-case ASCII by hand where an
  ecosystem is case-insensitive. Compare digit runs with `compareDigits`, never with `Number`, `parseInt`
  or `BigInt`. The vectors include 30-digit numbers.
- **No module-level mutable state and no caches.** Maven's nested lists may recurse. The 128-character
  guard bounds the depth.
- **Write the code from the rules below and the published specs.** Don't copy code from dpkg, rpm,
  apk-tools or php-src: they are under GPL and other licences.
- **The vendored vectors are the contract.** If a vector disagrees with a rule below, follow the vector,
  add a one-line comment next to the rule, and list the case in the PR. Widen a character set only when a
  vector needs it. The printable-ASCII guard never widens.

### 2. One comparer per ecosystem

Each file exports one `Comparer` constant. `semver.ts` also exports the parse and compare helpers that the
semver-based files reuse:

```ts
export interface SemverParts { core: string[]; pre: string[] | null; build: string[] | null }
export function parseSemver(v: string): SemverParts | null;
export function compareSemverParts(a: SemverParts, b: SemverParts, orderBuild: boolean): -1 | 0 | 1;
export const semver: Comparer;
```

| File | Export | Ecosystems | Rules |
| ---- | ------ | ---------- | ----- |
| `semver.ts` | `semver` | (shared) | SemVer 2.0 precedence, parsed as leniently as the vectors need |
| `npm.ts` | `npm` | npm | `semver` |
| `crates.ts` | `crates` | crates.io | `semver` |
| `hex.ts` | `hex` | Hex | `semver` |
| `swift.ts` | `swift` | SwiftURL | `semver` |
| `go.ts` | `go` | Go | `semver`, Go module forms |
| `github-actions.ts` | `githubActions` | GitHub Actions | `semver`, tag forms, no SHAs |
| `pub.ts` | `pub` | Pub | `semver`, but build metadata is ordered |
| `nuget.ts` | `nuget` | NuGet | NuGet versions |
| `pypi.ts` | `pypi` | PyPI | PEP 440 |
| `maven.ts` | `maven` | Maven | Maven `ComparableVersion` |
| `rubygems.ts` | `rubygems` | RubyGems | `Gem::Version` |
| `packagist.ts` | `packagist` | Packagist | Composer normalisation, then PHP `version_compare` order |
| `dpkg.ts` | `dpkg` | Debian, Ubuntu | dpkg |
| `alpine.ts` | `alpine` | Alpine | apk |
| `rpm.ts` | `rpm` | Red Hat | rpmvercmp |

The four one-line files (`npm`, `crates`, `hex`, `swift`) each carry a doc comment that names the upstream
rule (node-semver, Cargo, Elixir `Version`, SwiftPM). Then each wiring entry has its own file, and a later
ecosystem-specific rule has an obvious home.

**`semver`**
- An optional single leading `v`. `V1.2.3` is invalid.
- The core is 1 to 3 numeric parts. Missing parts are 0 (`1` = `1.0.0`). Leading zeros are ignored.
- Numeric parts after the third are treated as build metadata, so `1.2.3.4` orders as `1.2.3`. This follows
  the vectors' own comment.
- The prerelease comes after `-`. It is dot-separated identifiers, each non-empty `[0-9A-Za-z-]`.
  - Digit-only identifiers compare as numbers.
  - Other identifiers compare by code unit, case-sensitive (`1.2.3-5-Foo < 1.2.3-5-foo`).
  - A numeric identifier is lower than an alphanumeric one.
  - When one list is a prefix of the other, the shorter one is lower.
  - Any prerelease is lower than none.
- Build metadata comes after `+`, as dot-separated `[0-9A-Za-z-]`. It is ignored unless `orderBuild` is set.
- Anything else is invalid: `1..2`, `1.2.3-`, `1.2.3+`, `latest`.

**`go`**
- `semver` rules, with or without the `v`: Go modules use `v1.2.3`, but OSV Go data uses `1.2.3`.
- `vMAJOR` and `vMAJOR.MINOR` are shorthands for `.0`.
- `+incompatible` is build metadata.
- Pseudo-versions (`v0.0.0-20191109021931-daa7c04131f5`, `v1.2.4-0.2019…`, `v1.2.3-pre.0.2019…`) order as
  ordinary prereleases. This is how Go orders them, so they need no special case.
- Toolchain names (`go1.21.3`) are invalid.

**`githubActions`**
- `semver` rules, with or without the `v`. Workflow tags look like `v4` or `v4.1.0`. GHSA data looks like
  `46.0.1`.
- `v4` orders as `4.0.0`. Say in a doc comment that a floating tag is compared as its `.0` version.
- A 40-character hexadecimal commit SHA is never valid, even when it is all digits.

**`pub`**
- `semver` precedence with `orderBuild: true`, following pub_semver:
  - With an equal core and prerelease, a version with no build is lower than one with a build
    (`1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build`).
  - Build identifiers compare like prerelease identifiers (`1.2.3+900 < 1.2.3+a`).

**`nuget`**
- 1 to 4 numeric parts. Missing parts are 0 (`1.0` = `1.0.0.0`). Leading zeros are ignored
  (`1.0.01` = `1.0.1.0`). No leading `v`.
- The prerelease comes after `-`. It uses SemVer 2.0 identifier rules, but compares case-insensitively
  (`1.0.0-BETA` = `1.0.0-beta`).
- Build metadata after `+` is ignored (`1.0.0` = `1.0.0+beta`).

**`pypi`: PEP 440**
- **Normalisation**, all of it from the PEP:
  - case-insensitive, with an optional leading `v`;
  - separators `.`, `-` or `_` (or none) before the pre-release, post-release and dev parts;
  - spellings: `alpha`→`a`, `beta`→`b`, `c`/`pre`/`preview`→`rc`, `rev`/`r`→`post`;
  - an implicit number is 0 (`1.2a` = `1.2a0`, `1.2.post` = `1.2.post0`);
  - an implicit post-release: `1.0-1` = `1.0.post1`;
  - local separators `.`, `-` and `_` are all the same.
- **Order** is by these keys, in this order:
  1. epoch (default 0);
  2. the release, with trailing zeros dropped (`1.0` = `1.0.0`);
  3. the pre-release (`a < b < rc`, then its number). A dev release with no pre- or post-release sorts
     below every pre-release (`1.0.dev0 < 1.0a0`). No pre-release sorts above all;
  4. the post-release (none sorts lowest);
  5. the dev release (none sorts highest);
  6. the local part (none sorts lowest). Compare segments pairwise: a numeric segment beats a letter
     segment; numbers compare as numbers; letters compare by code unit. When one is a prefix of the other,
     more segments is higher.
- Invalid: `1.0-`, wildcards (`1.0.*`), and anything the guard rejects. PEP 440 trims whitespace, but MTI
  rejects it.
- **Legacy strings.** These are strings that old `packaging.version.LegacyVersion` accepted, such as
  `0.1-bulbasaur`. `valid()` is false for them. `compare` still orders them: below every PEP 440 version,
  and among themselves the way `LegacyVersion` did. The PyPI vectors' "legacy versions" block encodes this.

**`maven`: `ComparableVersion`**
- Lower-case ASCII.
- **Items.** `.` and `-` separate items. A switch between digits and letters also separates them, and acts
  like `-` (`1a1` → `1-a-1`). Each `-` opens a nested list. An item is a number, a string qualifier or a
  list.
- **Aliases.** `a`, `b` and `m` mean alpha, beta and milestone, but only when a digit follows directly.
  `cr` means `rc`. `ga`, `final` and `release` mean the empty qualifier.
- **Qualifier order:** `alpha < beta < milestone < rc < snapshot < "" < sp`. Unknown qualifiers sort after
  `sp`, in code-unit order.
- **Trailing nulls.** Drop trailing null items (0, `""` and its aliases) from each list before comparing,
  so `1.0.0` = `1` and `1-ga` = `1`.
- **Different kinds** at the same position: a qualifier is lower than a list, and a list is lower than a
  number. A missing item compares as null: 0 for numbers, `""` for qualifiers.
- `valid()` needs at least one digit and only letters, digits and `. - _ +`. So `r09` is valid and
  `RELEASE` is not.

**`rubygems`: `Gem::Version`**
- The string starts with a digit. Then come `.`-separated `[0-9A-Za-z]` segments, then an optional
  `-` prerelease. A `-` means `.pre.` (`1.0.0-beta` = `1.0.0.pre.beta`).
- Split segments at `.` and at each switch between letters and digits (`1.0.a10` → `1, 0, a, 10`).
- Any letter segment makes the version a prerelease.
- Drop trailing zero segments: `1.0` = `1`, `1.0.a` = `1.a`.
- Compare position by position, padding the shorter version with 0:
  - two numbers compare as numbers;
  - two letter segments compare by code unit;
  - a letter segment is lower than a number.

**`packagist`: Composer**
- **Normalise** as Composer's `VersionParser::normalize` does:
  - strip a leading `v` or `V`;
  - pad the numeric part to four numbers (`1.2` → `1.2.0.0`);
  - read a stability suffix after an optional `-`, `.` or `_`: `dev`, `alpha`/`a`, `beta`/`b`, `RC`/`rc`,
    `patch`/`pl`/`p` or `stable`, with an optional number.
- **Compare** the normalised strings as PHP's `version_compare` does:
  - split at `.`, `-`, `_` and `+`, and at each switch between digits and other characters;
  - numbers compare as numbers;
  - special words follow `other < dev < alpha = a < beta = b < RC = rc < # < pl = p`;
  - a number facing a word ranks like `#`.
- Branch versions (`dev-main`) can't be ordered, so they are invalid.

**`dpkg`: Debian Policy 5.6.12**
- **Format:** `[epoch:]upstream[-revision]`.
  - The epoch is the digits before the first `:` (default 0).
  - The revision is everything after the last `-`.
  - The upstream part starts with a digit and uses `[A-Za-z0-9.+~-:]`. It may contain `-` only when there
    is a revision, and `:` only when there is an epoch.
  - The revision uses `[A-Za-z0-9.+~]`.
- **Order:** compare the epoch as a number, then the upstream part, then the revision.
  - Each part alternates runs of non-digits and runs of digits.
  - Non-digit runs compare character by character: `~` sorts below the end of the run, the end of the run
    sorts below letters, and letters sort below other characters.
  - Digit runs compare as numbers. An empty run counts as 0.
- The osv-scalibr invalid case `1.2.3-not-a-debian:version!@#$` is invalid.

**`alpine`: apk**
- **Format:** numbers joined by `.`, then an optional single letter, then any number of `_suffix[digits]`,
  then an optional `-r<digits>`.
- **Order:**
  - suffixes: `_alpha < _beta < _pre < _rc < (none) < _cvs < _svn < _git < _hg < _p`;
  - a letter after the numbers sorts above no letter;
  - the `-r` revision compares last.
- Invalid strings order as the vectors' "invalid. do string sort" block says (code-unit order).
- The vectors note cases where apk 2.x and 3.x disagree. Follow the vectors, and list those lines in the
  PR.

**`rpm`: rpmvercmp**
- **Format:** `[epoch:]version[-release]`, with epoch 0 by default.
- **Order:** compare the epoch as a number, then the version, then the release, each with rpmvercmp:
  - skip separators (anything that is not a letter, a digit, `~` or `^`);
  - `~` sorts below everything, even the end of the string;
  - `^` sorts above the end of the string but below anything else;
  - next, take a run of digits or a run of letters. A digit run beats a letter run. Digit runs compare as
    numbers; letter runs compare by code unit, case-sensitive;
  - when one string runs out, the one with segments left is higher.
- The vectors' `# releases`, `# arch` and `# versions with colons that are not epochs` blocks decide the
  edge cases: a missing release, an arch suffix, and a colon that isn't an epoch.

### 3. `comparerFor` (`index.ts`)

Build a `Map<Ecosystem, Comparer>` holding all 16 entries (`Debian` and `Ubuntu` both map to `dpkg`).
`comparerFor` returns `map.get(ecosystem) ?? null`. Use a `Map` rather than an object literal, so a runtime
string such as `constructor` or `__proto__` from a database row returns `null`, not an `Object.prototype`
member. An ecosystem added to `ECOSYSTEMS` later with no comparer still gets `null`.

### 4. `inRange` changes (`index.ts`)

Keep the walk that seams built, which takes the comparer as an argument so the toy-comparer tests still
apply. Make two changes.

1. **Open-ended rows match first.** A `SEMVER` or `ECOSYSTEM` row with `introduced === '0'`, `fixed === null`
   and `last_affected === null` returns `true` for any version string, before looking up a comparer.
   - This covers every malicious-package record ("every version"), and distro records with no fix yet.
   - `EXACT` rows are excluded. They also store `introduced: '0'` (the column default), and must keep
     matching by their `versions` list.
2. **No guessing on bad input.** For a ranged row with a comparer, return `'unsupported'` in two cases:
   - `valid(version)` is false;
   - a bound the row uses (`introduced` other than `'0'`, `fixed`, `last_affected`) is not valid.

   Without this guard, `compareInvalid` would give a confident wrong answer.

`SEMVER` and `ECOSYSTEM` rows both keep using the ecosystem's comparer, as today. In the fixtures, `SEMVER`
rows are Go records and open-ended malicious-package records. For Go both orders agree, and the open-ended
rows never reach a comparer.

### 5. Test vectors (`fixtures/versions/`)

Put the files in subfolders. The shared `test/fixtures.ts` glob (`fixtures/*/*`) then picks up only
`SOURCE.md`, and never inlines 1.6 MB of vectors into every test that uses fixtures.

All files use osv-scalibr's line format. Blank lines are skipped. Lines starting with `# ` or `// ` are
comments. Every other line is exactly `a <op> b`, split on single spaces, where `<op>` is `<`, `=` or `>`.
Each line is checked in both directions.

**`osv-scalibr/`: vendored unchanged.**
- Source: [google/osv-scalibr](https://github.com/google/osv-scalibr), `semantic/testdata/`.
- Commit: `ce5ed63433445d0fd593efb273a18b87c57f02bc` (25 Nov 2026).
- Licence: Apache-2.0, Copyright Google LLC.
- Fetch each file from
  `https://raw.githubusercontent.com/google/osv-scalibr/<commit>/semantic/testdata/<file>`.
- Check each with `git hash-object`. If a blob SHA differs from the table, stop and say so.

| File | Bytes | Blob SHA |
| ---- | ----- | -------- |
| `semver-versions.txt` | 2056 | `9ad42ec67393236284aad0ffca7b148a0b1225ef` |
| `pub-versions.txt` | 2450 | `cb2143ab88a78f4e93cc31a2e077922b04aae96f` |
| `nuget-versions.txt` | 1060 | `ac940baea3057f634d7c33bcca3412f1ee9d4273` |
| `pypi-versions.txt` | 1280 | `d7d1dd917855127ab8d3d600422712ca70d8a136` |
| `pypi-versions-generated.txt` | 217760 | `2af318c3cdab5af0bf7b461a08dd26b243a5bffc` |
| `maven-versions.txt` | 1848 | `d3d5ff15a41af1563bfa4ca2ca352aa08128e2e4` |
| `maven-versions-generated.txt` | 303561 | `3b24fc570e990a7e143761b367f364213fd3198b` |
| `rubygems-versions.txt` | 622 | `78ea3515c1260077f06a1cdf94e57960d2a6ae16` |
| `rubygems-versions-generated.txt` | 71880 | `f07e2529a2a6c118801da334d89767031b47ab88` |
| `packagist-versions.txt` | 1984 | `dd3f4cb8ecf8b07659d61761fc1df3b75d921b4f` |
| `packagist-versions-generated.txt` | 201633 | `8b50879510e492127b1d75cb769ff08301955854` |
| `debian-versions.txt` | 701 | `1672bcd3cb831192a5a5185a2bda99fa3f9b8548` |
| `debian-versions-generated.txt` | 451277 | `91b2b43f74f9f310e3f90c96332821fc117249cc` |
| `alpine-versions.txt` | 13776 | `53258da2547ee0025bc0d93831fbb666171e6f1e` |
| `alpine-versions-generated.txt` | 301708 | `2172125a79909906344d59fe3185556268f8cc6d` |
| `redhat-versions.txt` | 2757 | `34d35d44b658e3ca18872a344bd3c9d8055e9a4a` |

Skip `cran-*` and `hackage-*`: MTI has no data for those ecosystems.

**`osv-dev/maven.txt`: ported.**
- Source: [google/osv.dev](https://github.com/google/osv.dev) `osv/ecosystems/maven_test.py`.
- Commit: `d60b14dd943e35d7b790c8649da2804bd9e48a01`. Licence: Apache-2.0.
- Port the in-memory ordering tests: `test_versions_qualifiers`, `test_versions_number`,
  `test_versions_order`, `test_versions_order_mng_5568`, `test_versions_order_mng_6572` and
  `test_versions_equal`.
  - Each ordered list becomes `a < b` lines for its adjacent pairs.
  - Each equal group becomes `a = b` lines.
  - Start each block with `# from osv/ecosystems/maven_test.py::<test>`.
- This is what covers `sp` (`1 < 1-sp < 1-sp2 < 1-sp123 < 1-abc`), which the scalibr Maven files lack.
- Leave out the tests that need recorded HTTP, and any case that uses osv.dev's `0` sentinel.
- osv.dev's other ecosystem tests add little to the scalibr files, and they encode osv.dev conventions MTI
  doesn't follow (`0` sorts first; invalid sorts last). Don't port them.
- Its `testdata/packagist_test_cases.txt` names the same upstream sources as scalibr's
  `packagist-versions.txt`. Vendor it only if it has lines that scalibr's lacks.

**`standards/`: from the published specs.**

`semver-org.txt` holds the precedence and build-metadata examples from
[SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) §10–11 (CC BY 3.0, Tom Preston-Werner):

```
1.0.0 < 2.0.0
2.0.0 < 2.1.0
2.1.0 < 2.1.1
1.0.0-alpha < 1.0.0-alpha.1
1.0.0-alpha.1 < 1.0.0-alpha.beta
1.0.0-alpha.beta < 1.0.0-beta
1.0.0-beta < 1.0.0-beta.2
1.0.0-beta.2 < 1.0.0-beta.11
1.0.0-beta.11 < 1.0.0-rc.1
1.0.0-rc.1 < 1.0.0
1.0.0-alpha+001 = 1.0.0-alpha
1.0.0+20130313144700 = 1.0.0
1.0.0-beta+exp.sha.5114f85 = 1.0.0-beta
```

`pep440.txt` holds examples from [PEP 440](https://peps.python.org/pep-0440/) (public domain):

- The ordering example as 19 `<` lines: `1.dev0`, `1.0.dev456`, `1.0a1`, `1.0a2.dev456`, `1.0a12.dev456`,
  `1.0a12`, `1.0b1.dev456`, `1.0b2`, `1.0b2.post345.dev456`, `1.0b2.post345`, `1.0rc1.dev456`, `1.0rc1`,
  `1.0`, `1.0+abc.5`, `1.0+abc.7`, `1.0+5`, `1.0.post456.dev34`, `1.0.post456`, `1.0.15`, `1.1.dev1`.
- The normalisation examples as `=` lines:
  - `1.1RC1 = 1.1rc1`, `00 = 0`, `09000 = 9000`;
  - `1.1.a1 = 1.1a1`, `1.1-a1 = 1.1a1`, `1.1_a1 = 1.1a1`, `1.0a.1 = 1.0a1`;
  - `1.1alpha1 = 1.1a1`, `1.1beta2 = 1.1b2`, `1.1c3 = 1.1rc3`, `1.0pre1 = 1.0rc1`, `1.0preview1 = 1.0rc1`;
  - `1.2a = 1.2a0`;
  - `1.2-post2 = 1.2.post2`, `1.2post2 = 1.2.post2`, `1.2.post-2 = 1.2.post2`;
  - `1.0-r4 = 1.0.post4`, `1.0rev4 = 1.0.post4`, `1.2.post = 1.2.post0`, `1.0-1 = 1.0.post1`;
  - `1.2-dev2 = 1.2.dev2`, `1.2dev2 = 1.2.dev2`, `1.2.dev = 1.2.dev0`;
  - `1.0+ubuntu-1 = 1.0+ubuntu.1`, `v1.0 = 1.0`, `1.0 = 1.0.0`.
- One epoch line: `1!1.0 > 2.0`.

**`mti/`: written for this repo (Apache-2.0)**, where the published files have gaps.
- Check each line with the real tool when the sandbox has it (`dpkg --compare-versions`, Python
  `packaging`), and say in the PR which lines were checked.
- `go.txt`:
  ```
  v1.2.3 = 1.2.3
  v1 = v1.0.0
  v1.2 = v1.2.0
  0.51.0 < v0.52.0
  v0.0.0-20191109021931-daa7c04131f5 < v0.0.0
  v0.0.0-20191109021931-daa7c04131f5 < v0.0.0-20200101000000-0123456789ab
  v1.2.3 < v1.2.4-0.20191109021931-daa7c04131f5
  v1.2.4-0.20191109021931-daa7c04131f5 < v1.2.4
  v1.2.3-pre < v1.2.3-pre.0.20191109021931-daa7c04131f5
  v1.2.3-pre.0.20191109021931-daa7c04131f5 < v1.2.3
  v2.0.0+incompatible = v2.0.0
  v1.9.9 < v2.0.0+incompatible
  v2.0.0+incompatible < v2.0.1+incompatible
  ```
- `github-actions.txt`: `v4 = 4.0.0`, `v4.1 = 4.1.0`, `46.0.1 = v46.0.1`, `v46.0.0 < 46.0.1`,
  `v3.9.9 < v4`, `v4.0.0-beta.1 < v4`.
- `nuget.txt`: `1.0.0.1 > 1.0.0`, `1.0.0.0 = 1.0.0`, `1.0 = 1.0.0`, `1.0.0-ALPHA.10 > 1.0.0-alpha.9`,
  `1.0.0-rc.1 < 1.0.0`, `1.0.0+build.5 = 1.0.0`.
- `maven.txt`: `1-alpha-1 < 1-beta-1`, `1-beta-1 < 1-milestone-1`, `1-milestone-1 < 1-rc-1`,
  `1-rc-1 = 1-cr-1`, `1-rc-1 < 1-SNAPSHOT`, `1-SNAPSHOT < 1`, `1 = 1-ga`, `1 = 1.final`, `1 = 1-release`,
  `1 < 1-sp`, `1.0.0 = 1`, `2.0-beta9 < 2.0-rc1`, `2.0-rc1 < 2.0`, `2.13.0 < 2.14.1`, `2.14.1 < 2.15.0`.
- `dpkg.txt`:
  ```
  1.0~~ < 1.0~~a
  1.0~~a < 1.0~
  1.0~ < 1.0
  1.0 < 1.0a
  1:1.0 > 2.0
  1.0-1 < 1.0-1ubuntu1
  1.0-1ubuntu1 < 1.0-2
  3.0.2-7ubuntu2.13 < 3.0.2-7ubuntu2.14
  4.15.0-1023.24~14.04.1 < 4.15.0-1023.24
  1:1.43.11+dfsg-2 < 1:1.43.12+dfsg-1~deb13u1
  1:1.43.12+dfsg-1~deb13u1 < 1:1.43.12+dfsg-1
  ```
- `rpm.txt`: `1.0~rc1 < 1.0`, `1.0 < 1.0^post1`, `1.0^post1 < 1.0.1`, `1.0a < 1.0.1`, `1:1.0 > 2.0`,
  `1.2.3-4.el8 = 0:1.2.3-4.el8`, `0:1.2.3-4.el8 < 0:1.2.3-5.el8`, `1.2.3-4.el8_9 > 1.2.3-4.el8`.

**`SOURCE.md`** follows the repo's fixture convention (a `SOURCE.md` in each folder). For each subfolder it
names:
- the source URL, commit, licence and copyright holder;
- whether each file was copied unchanged (with its blob SHA) or ported, and from which test;
- the upstream origins that scalibr's own comments name: php-src
  `ext/standard/tests/versioning/version_compare.phpt` and composer/semver `tests/ComparatorTest.php` for the
  Packagist files, and apk-tools `tests/version.data` for the Alpine file;
- semver.org (CC BY 3.0, with attribution) and PEP 440 (public domain);
- that `mti/` was written here.

**NOTICE doesn't change.** Apache-2.0 §4(d) only requires carrying over an upstream NOTICE file, and
neither osv-scalibr nor osv.dev has one at the pinned commits. Credit lives in `SOURCE.md`. The NOTICE line
"no third-party vulnerability … data" stays true: version lists aren't vulnerability data. Say this in the
PR.

### 6. Workers test project (`packages/core/vitest.workers.mts`)

Copy the patterns project, which has no bindings. The root config picks it up through its
`packages/*/vitest.workers.mts` glob, with no edit there.

```ts
export default defineProject({
  root: import.meta.dirname,
  plugins: [cloudflareTest({ miniflare: { compatibilityDate: '2026-11-01', compatibilityFlags: ['nodejs_compat'] } })],
  test: { name: 'core', include: ['src/**/*.workers.test.ts'] },
});
```

## Tests

All files live in `packages/core/src/versions/`. Everything except the benchmark runs in `pnpm build`.

- **`test-support.ts`** (shared by the tests, not imported by product code):
  - `parseVectors(text)` returns `{ line, a, op, b }[]`. It throws on a malformed line, so a broken file
    fails loudly.
  - `VECTOR_FILES` maps each path under `fixtures/versions/` to the ecosystems it applies to:
    - `osv-scalibr/semver-versions.txt`: npm, crates.io, Go, Hex, SwiftURL, GitHub Actions;
    - `standards/semver-org.txt`: the same six, plus NuGet;
    - `osv-scalibr/debian-*` and `mti/dpkg.txt`: Debian and Ubuntu;
    - every other file: the one ecosystem its name says.
  - `SMALL_VECTORS` is a `?raw` glob of `fixtures/versions/*/*.txt` that excludes `*-generated.txt`
    (negative pattern). It keeps the Workers bundle small.
  - `benchPairs()` returns 10,000 `{ ecosystem, a, b, op }` items, built by cycling through
    `SMALL_VECTORS` for all 16 ecosystems in a fixed order.
- **`vectors.test.ts`** globs every `fixtures/versions/*/*.txt`.
  - Every line passes both ways for each mapped ecosystem.
  - Both versions on every line are `valid()`, except entries on a short exemption list in the test (the
    Alpine invalid block and the PyPI legacy lines, each with a reason).
  - Per-file counts are printed.
  - Every name in `ECOSYSTEMS` appears in `VECTOR_FILES`, and every `.txt` file is in `VECTOR_FILES`
    (no orphan files).
- **`valid.test.ts`**
  - For every comparer, `valid()` is false for: `''`, 129 characters, `'1.0.0\n'`, `'1.0.0\u0000'`,
    `'\u007f'`, `' 1.0.0'`, `'1.0.0\t'`, `'１.２.３'`, `'1.0.0é'`, `'1.0‮'`, `undefined`, `null`, `1`
    and `{}`.
  - A 1,000,000-character string returns false in under 1 ms on average over 1,000 calls.
  - Per-ecosystem accept and reject lists:
    - semver: accepts `v1.2.3-rc.1+b.5`; rejects `V1.2.3` and `1.2.3-`;
    - Go: accepts `v0.0.0-20191109021931-daa7c04131f5`, `v2.0.0+incompatible` and `0.52.0`; rejects
      `go1.21.3` and `master`;
    - GitHub Actions: rejects `'1'.repeat(40)` and `'a5ac7e51b41094c92402da3b24376905380afc29'`;
    - PyPI: accepts `1!2.0.post1.dev3+local.7`; rejects `1.0-`, `1.0.*` and `0.1-bulbasaur`;
    - Maven: accepts `r09`; rejects `RELEASE`;
    - NuGet: rejects `1.2.3.4.5`;
    - Packagist: rejects `dev-main`;
    - Debian: rejects `1.2.3-not-a-debian:version!@#$`.
- **`index.test.ts`.** Seams' walk tests stay. Replace "every ecosystem returns `'unsupported'`" with:
  - every `ECOSYSTEMS` entry has a comparer;
  - `comparerFor` returns `null` for `CRAN`, `constructor` and `__proto__`.

  Add rows shaped like real advisories:
  - PyPI `[0, 1.3.0)`: `1.2.0` true, `1.3.0rc1` true, `1.3.0` false, `1.3.0.post1` false.
  - Maven `[2.13.0, 2.15.0)`: `2.14.1` true, `2.15.0` false. Maven `[2.0-beta9, 2.3.1)`: `2.0-rc1` true,
    `2.0-beta8` false.
  - Go `SEMVER [0, 0.52.0)`: `v0.51.0` true, `v0.0.0-20240101000000-abcdefabcdef` true, `v0.52.0` false.
  - Debian `[0, 1:1.43.12+dfsg-1~deb13u1)`: `1:1.43.11+dfsg-2` true, the fixed version false,
    `1:1.43.12+dfsg-1` false.
  - Ubuntu `[0, 3.0.2-7ubuntu2.14)`: `3.0.2-7ubuntu2.13` true.
  - npm `[1.0.0, last_affected 1.2.0]`: `1.2.0` true, `1.2.1` false, `0.9.0` false.
  - An open-ended row matches for every one of the 16 ecosystems, and for `CRAN`, with versions `35.7.4`
    and `not a version`.
  - An `EXACT` row with `introduced: '0'` still matches only its listed versions.
  - A ranged npm row with version `latest`, or with `fixed: 'x.y'`, gives `'unsupported'`.
- **`fuzz.test.ts`**
  - Use a seeded PRNG written in the test (for example mulberry32), so a failure reproduces from its seed.
    Don't add a fuzzing library.
  - Inputs for each comparer:
    - 2,000 random strings of length 0 to 200 over printable ASCII;
    - 2,000 strings over the version alphabet (digits, `.-+~^:!_v`, and the tokens `a b rc alpha beta dev
      post pre sp snapshot final ga pl p r git cvs svn hg incompatible`);
    - fixed pathological strings: 128 × `9`, 64 × `1.`, 128 × `-`, 128 × `~`, 64 × `1-`, 64 × `a1`,
      128 × `0`;
    - control characters, lone surrogates, emoji, and strings of 129, 10,000 and 1,000,000 characters.
  - Properties:
    - nothing throws;
    - `valid` returns a boolean;
    - `compare` returns only -1, 0 or 1, gives 0 against itself, and gives the opposite sign when swapped;
    - transitivity: draw 150 valid versions from the ecosystem's vector files (seeded), sort them with
      `compare`, then check that every pair `i < j` gives `compare ≤ 0`.
  - CPU budget, timed with `performance.now()`:
    - the slowest single `valid` or `compare` call is under 10 ms;
    - each comparer's fuzz run is under 500 ms;
    - the whole `src/versions` suite (including the vectors) is under 5 s on a laptop.
  - If a transitivity failure comes from rules the vectors require, record the triple in the PR, and leave
    out only that input shape from the transitivity check.
- **`no-regex.test.ts`.** Parse every non-test `.ts` file in `src/versions/` with the TypeScript compiler
  API (`typescript` is already a root dev dependency). Fail on any regular-expression literal and on any
  identifier `RegExp`.
- **`bench.test.ts`** (Node). Every item from `benchPairs()` gives its expected answer. A wrong comparer then
  fails `pnpm build`, not only the Workers run.
- **`bench.workers.test.ts`** (Workers).
  - Build `benchPairs()` and look up the comparers outside the timed part.
  - Run once to warm up, then 5 timed runs of all 10,000 `compare` calls. Count wrong answers inside the
    loop, so the work can't be skipped.
  - Afterwards, assert zero wrong answers. Assert the median is under the 250 ms ceiling (generous, for CI
    machines). Assert that at least one run measured above 0 ms, or fail with "clock didn't advance".
  - Print `versions bench: median <ms> ms for 10000 comparisons`.

## Not in scope

- OSV `limit` events and `GIT` ranges: there is no column for them, and `GIT` ranges aren't written.
- Ecosystem release suffixes (`Debian:13`, `Ubuntu:22.04:LTS`, `Alpine:v3.20`). Whoever writes `affected`
  rows handles them. Comparers only see version strings.
- `EXACT` rows. They keep plain string equality.
- Resolving a floating GitHub Actions tag (`v4`) to the release it points at, or comparing a commit-SHA pin.
- Go toolchain and standard-library strings (`go1.21.3`).
- Ecosystems outside `ECOSYSTEMS` (CRAN, Hackage, openSUSE, Wolfi and others).
- Choosing `upgradeTo`, ranking and wording. These belong to the package-check route.
- Normalising versions for storage or display, and checking ranges when data is written.

## Acceptance criteria

1. `pnpm build` passes. `pnpm test:workers` passes, and its output includes the `core` project.
2. `git diff --name-only main` lists only paths under `packages/core/src/versions/` and `fixtures/versions/`,
   plus `packages/core/vitest.workers.mts`. `pnpm install --frozen-lockfile` passes, and the lockfile is
   unchanged.
3. `comparerFor` returns a comparer for each of the 16 `ECOSYSTEMS` names, and `null` for `CRAN`,
   `constructor`, `__proto__` and `''`.
4. Every line of every vector file passes in both directions for every ecosystem mapped to it. The PR lists
   the line count per file, the exemption count, and every case where a vector overrode a rule in this spec.
5. The 16 vendored files match the blob SHAs in `SOURCE.md` (`git hash-object` output saved). `SOURCE.md`
   names each source, commit, licence and credit.
6. The `inRange` cases in Tests pass. In particular, an open-ended row matches any version for any ecosystem
   name, an `EXACT` row does not, and a ranged row with an unparseable version or bound gives `'unsupported'`.
7. The fuzz suite passes: no throws, the order properties hold, the slowest call is under 10 ms, and the
   whole versions suite is under 5 s. The PR quotes the suite's time.
8. Every comparer passes the `valid()` rejection list, including the 1,000,000-character case.
9. `no-regex.test.ts` passes. No file under `src/versions/` imports anything outside `src/versions/` except
   `../packages` (for the `Ecosystem` type and `ECOSYSTEMS`) and test tooling.
10. The Workers benchmark's median for 10,000 comparisons is under 50 ms. The PR quotes the printed figure,
    says where it ran, and links the Workers timer docs. The test itself fails above 250 ms, or if the clock
    doesn't move.
11. The PR says NOTICE is unchanged, and why.

## Decisions added at review

- **OS ecosystem keys carry a release,** exactly as OSV writes them (`Debian:12`, `Ubuntu:22.04:LTS`,
  `Alpine:v3.20`). `comparerFor` maps any key that starts `Debian:` or `Ubuntu:` to the dpkg comparer and
  `Alpine:` to the apk comparer. Test this mapping.
- **Licences of test data:** don't vendor any test line that the upstream file marks as taken from a GPL
  project (the php-src or composer lines in the Packagist file and the apk-tools lines in the Alpine file).
  Write our own cases for those comparers instead, from the published version rules, and say so in
  `fixtures/versions/SOURCE.md`. Every vendored line must be Apache-2.0, CC BY or public domain.
