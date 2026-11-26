# packages-check-api: check up to 1,000 packages against MTI in one call

## Why

People and agents want to know which of their dependencies have known problems, and how urgent each one is.
`POST /v1/packages/check` answers that from MTI's own data. The web app, the MCP server's `check_packages`
tool, CI checks and alert emails will all call it. After mcp-seams the route answers 501.

This change builds it. The route takes up to 1,000 packages and refuses bad or risky input without echoing
it. It charges a daily quota, looks the packages up in the `affected` table and ranks each one. It suggests an
upgrade only when MTI can stand behind that version.

A dependency list shows a company's stack and its unpatched bugs. So the route stores nothing but a usage
count, logs only counts and timing, and never sends a package name anywhere else.

## Current state (on main after mcp-seams)

| Area | On main |
| ---- | ------- |
| `apps/api/src/routes/packages.ts` | `POST /v1/packages/check`: `requireUser`, then `notImplemented` (501). Already mounted in `index.ts` |
| `@ti/core/packages` | `ECOSYSTEMS`, `canonicalEcosystem`, `normaliseName`, `parsePurl` (drops qualifiers), `rankPriority`, `MAX_CHECK_PACKAGES = 1000`, the zod request schema, and `CheckRequest`, `CheckMatch`, `CheckResult`, `CheckResponse`, `RejectedEntry` (six reasons). Each entry is `{ ecosystem, name, version }` or `{ purl }` |
| `@ti/core/versions` | `comparerFor` returns null for every ecosystem. `inRange` matches `EXACT` rows by string and returns `'unsupported'` for every other range. Comparers arrive in a separate change |
| `ti_advisories` | `affected` (key `ecosystem, name, source, source_id, range_no`; `vuln_key`, `range_type`, `introduced`, `fixed`, `last_affected`, `versions`) and `package_advisories` (key `source, source_id`; `status`, `summary`, `severity`, `reviewed`, `url`, `published`, `modified`). Both are empty until the package data load runs |
| `ti_users` | `package_usage (user_id, day, packages, calls)`, key `user_id, day`. `deleteUserData` removes a user's rows |
| `ti_vulns.vulns` | Hot set only: published since 2024-01-01, in KEV, with a public exploit, or EPSS ≥ 0.1. Columns used here: `key, kind, title, cvss, cvss_source, epss, kev_added, ransomware, exploit_public` |
| `ti_signals.signals` | Key `vuln_key, kind, source, ref`. Kinds `exploited_wild`, `public_exploit`, `detection`, `poc`, `ransomware` |
| Malicious data | Source id `openssf-malicious-packages` (written by the `osv-malicious` parser), ids `MAL-…`, `vulns.kind = 'mal'`. The `osv` source can also carry `MAL-` ids |
| Licences | `packages/core/src/licence.ts` `displayMode` (`full` / `link` / `hidden`; `wait` is hidden). `lib/preview.ts` `displayFor(SETTINGS, ids)` (unknown ids are hidden) and `lib/credits.ts` `creditsFor`. `routes/entries.ts` drops hidden advisories, ignores signals from hidden sources, and nulls `cvss` when `cvss_source` is hidden |
| Auth | `requireUser` sets `userId` from `currentUserId(c)`: the MCP identity's `sub`, else the Clerk session. `POST /v1/packages/check` is on the MCP route allow-list with scope `mti:read`. `rateLimit` keys both kinds of caller as `u:<id>` on `RL_USER` |
| Logs | `logEvent` (`@ti/core/log`) writes one JSON line with primitives only. The `request` line logs the route pattern, status, ms and user id. `guarded()` logs the route and error name only |
| Web | Entry pages are `/e/:id`. `SITE_ORIGIN` is in `Bindings` |
| D1 | At most 100 bound parameters per statement |
| Tests | `account.workers.test.ts` mounts routes on a test app whose middleware sets `clerkAuth` from `x-test-user`, and fails on any unexpected `fetch`. `launch.workers.test.ts` uses `createApp(stubClerk)`, env overrides and console spies |

If `affected`, `package_usage`, `@ti/core/packages`, `@ti/core/versions` or the 501 stub is missing on main,
stop and say so.

## What to build

Touch only:

- `apps/api/src/routes/packages.ts`;
- new `apps/api/src/lib/packages-*.ts`;
- `packages/core/src/packages.ts`, for the type extensions in section 1;
- new tests: `apps/api/test/packages-check.workers.test.ts`, `apps/api/test/packages-input.test.ts`,
  `apps/api/test/packages-match.test.ts`.

No migrations. No changes to `packages/core/src/versions/**`, `packages/linker/**`, `apps/mcp/**`,
`apps/api/src/index.ts`, the MCP route allow-list or any config file.

### 1. Type extensions (`packages/core/src/packages.ts`)

Add fields and types. Remove or rename nothing.

```ts
// Each request entry gains `private?: boolean`: { ecosystem, name, version, private? } | { purl, private? }.
// The zod request schema gains the same optional field. That is the only non-type change in this file.

export interface RejectedEntry { index: number; reason: 'bad_entry' | 'bad_ecosystem' | 'bad_name' | 'bad_version'
  | 'bad_purl' | 'bad_characters' | 'looks_like_url' | 'looks_like_secret' | 'duplicate' }  // three new reasons

/** Values used in CheckMatch.signals. */
export type MatchSignal = 'malicious' | 'exploited_wild' | 'ransomware' | 'public_exploit' | 'poc';

export interface CheckMatch { id: string; title: string | null; summary: string | null;  // summary is new
  fixedIn: string | null; signals: string[]; cvss: number | null; epss: number | null; url: string; sources: string[] }
export interface CheckResult { package: PackageRef; priority: Priority; upgradeTo: string | null;
  upgradeNote: string | null; matches: CheckMatch[]; omitted: number }                      // omitted is new
/** Records that name this package but whose version ranges MTI can't evaluate yet. */
export interface UncertainEntry { package: PackageRef; ids: string[]; reason: 'version_rules_pending' }
/** A package marked private whose name is also a known malicious public package. */
export interface ConfusionWarning { package: PackageRef; ids: string[]; reason: 'public_malicious_name' }
export interface CheckResponse { asOf: string; checked: number; matched: number;
  summary: Record<Priority, number>; results: CheckResult[]; noRecord: PackageRef[];
  uncertain: UncertainEntry[]; confusion: ConfusionWarning[];                                  // new
  rejected: RejectedEntry[]; notes: string[]; credits: Credit[] }                              // credits is new
```

`Credit` is a type import from `./api`. `CheckMatch.signals` holds `MatchSignal` values only.

### 2. Input (`apps/api/src/lib/packages-input.ts`)

Pure code, no bindings.

```ts
export interface CheckEntry { index: number; ref: PackageRef; private: boolean }
export function readCheckBody(input: unknown):
  | { ok: true; entries: CheckEntry[]; rejected: RejectedEntry[] }
  | { ok: false; error: 'invalid_body' | 'too_many_packages' };
```

**The envelope** is the zod schema from `@ti/core/packages`: exactly `{ packages }`, an array of 1 to
`MAX_CHECK_PACKAGES` items. Over 1,000 items gives `too_many_packages`. Anything else wrong with the envelope
gives `invalid_body`. Items are checked one by one, so one bad entry never fails the whole request.

**Each entry** goes through these steps in order. The first failure wins. Only `{ index, reason }` is kept; the
value itself is dropped at once.

1. **Shape.** A strict object: `{ ecosystem, name, version, private? }` or `{ purl, private? }`. Strings stay
   under raw caps (ecosystem 40, name 512, version 256, purl 1,024 characters), and `private` is a boolean. An
   entry that is not an object, mixes the two forms or has another key gets `bad_entry`.
2. **Characters**, on every raw string. Reject:
   - controls and DEL (`\p{Cc}`);
   - format characters (`\p{Cf}`), which cover zero-width (U+200B–U+200D, U+2060, U+FEFF), bidi
     (U+200E, U+200F, U+061C, U+202A–U+202E, U+2066–U+2069) and Unicode Tag (U+E0000–U+E007F) characters;
   - variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF);
   - private-use and unassigned code points.

   Any of these gives `bad_characters`.
3. **URLs.** `://` anywhere gives `looks_like_url`. In a purl, only the part before the first `?` or `#` is
   checked here, because `parsePurl` drops qualifiers and subpath unread.
4. **Secrets**, on every raw string. For a purl this includes qualifiers, percent-decoded. Each of these gives
   `looks_like_secret`:
   - a credential in a URL authority: `/[^\s\/:@]+:[^\s\/@]+@/` (`user:pass@`);
   - a known token prefix followed by a token-shaped tail (table below). The tail rule keeps real names such
     as `pypi-simple` and `sk-utils` valid;
   - a run of 32 or more characters from `[A-Za-z0-9+/=_-]` with Shannon entropy of at least 4.3 bits per
     character and at least 0.3 changes between upper case, lower case and digit per character. Long package
     paths are low on the second measure; tokens are high on both;
   - a run of 32 or more hex digits. One exception: a version that is exactly 40 lower-case hex digits, which
     is a commit pin (common for GitHub Actions).

   Tune the two thresholds only against the corpora in Tests. Never drop a corpus value to make a rule pass.
5. **purl.** `parsePurl`; failure gives `bad_purl`. The decoded name and version then go through steps 2–4
   again, so `%E2%80%8B` or an encoded token is caught.
6. **Ecosystem.** `canonicalEcosystem`; null gives `bad_ecosystem`.
7. **Name.** NFKC, then `normaliseName`, then the ecosystem's grammar below as a whole-string match. A null or
   a miss gives `bad_name`.
8. **Version.** At most 128 characters, and the ecosystem's grammar below. A miss gives `bad_version`. For Go,
   drop one leading `v`, because OSV stores Go versions without it. Range syntax (`^1.2`, `~1.2`, `>=1`,
   `1.x`, `*`) never passes: the route checks installed versions.
9. **Duplicates.** The key is ecosystem, normalised name and version. The first entry stays and later ones get
   `duplicate`. If any copy says `private: true`, the kept entry is private.

| Token prefix | Tail that must follow |
| ------------ | --------------------- |
| `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | 30 or more of `[A-Za-z0-9]` |
| `github_pat_` | 20 or more of `[A-Za-z0-9_]` |
| `npm_` | 30 or more of `[A-Za-z0-9]` |
| `sk-` | 20 or more of `[A-Za-z0-9_-]` |
| `xox` plus one of `a b p o s r`, then `-` | 10 or more of `[A-Za-z0-9-]` |
| `AKIA` | 16 of `[A-Z0-9]` |
| `glpat-` | 20 or more of `[A-Za-z0-9_-]` |
| `pypi-` | 50 or more of `[A-Za-z0-9_-]` |

**Names**, checked after `normaliseName`:

| Ecosystem | Grammar (whole string) | Max |
| --------- | ---------------------- | --- |
| npm | `(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*` | 214 |
| PyPI | `[a-z0-9]([a-z0-9-]*[a-z0-9])?` | 214 |
| crates.io | `[a-z][a-z0-9-]{0,63}` | 64 |
| Go | `stdlib`, `toolchain`, or `[a-z0-9.-]+\.[a-z0-9.-]+(/[A-Za-z0-9._~+-]+)*` | 256 |
| Maven | `[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+` | 256 |
| RubyGems | `[A-Za-z0-9_.-]+` | 214 |
| NuGet | `[a-z0-9_.-]+` | 214 |
| Packagist | `[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]\|-{1,2})?[a-z0-9]+)*` | 214 |
| Hex | `[a-z][a-z0-9_]*` | 214 |
| Pub | `[a-z_][a-z0-9_]*` | 214 |
| SwiftURL | `[a-z0-9.-]+\.[a-z]{2,}(/[A-Za-z0-9._~-]+)+` (no scheme) | 256 |
| GitHub Actions | `[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?` | 256 |
| Debian, Ubuntu | `[a-z0-9][a-z0-9.+-]+` | 214 |
| Alpine, Red Hat | `[A-Za-z0-9][A-Za-z0-9._+-]*` | 214 |

**Versions** (all at most 128 characters):

| Ecosystem | Grammar (whole string) |
| --------- | ---------------------- |
| npm, crates.io, Hex, Pub, SwiftURL | SemVer 2.0.0 (the regular expression published on semver.org) |
| Go | SemVer 2.0.0 after dropping one leading `v` (pseudo-versions and `+incompatible` pass) |
| PyPI | PEP 440 `VERSION_PATTERN` (Appendix B), case-insensitive |
| NuGet | `\d+(\.\d+){1,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?` |
| RubyGems | `\d+(\.[0-9A-Za-z]+)*(-[0-9A-Za-z_.-]+)?` (platform suffix allowed) |
| Debian, Ubuntu | `(\d+:)?\d[A-Za-z0-9.+~-]*` |
| Red Hat | `(\d+:)?[A-Za-z0-9][A-Za-z0-9._+~^-]*` |
| Maven, Packagist, GitHub Actions, Alpine | `[A-Za-z0-9][A-Za-z0-9._+~-]*` |

These grammars only decide what is well formed. Version order belongs to the comparers.

### 3. Daily quota (`apps/api/src/lib/packages-quota.ts`)

```ts
export const DAILY_PACKAGE_QUOTA = 20_000;
export type QuotaResult = { ok: true; used: number } | { ok: false; remaining: number; retryAfter: number };
/** One statement. Throws on any D1 error; the route then answers 503. */
export function chargeQuota(db: D1Database, userId: string, count: number, now: Date): Promise<QuotaResult>;
export function refundQuota(db: D1Database, userId: string, count: number, now: Date): Promise<void>;
/** Whole seconds until the next 00:00 UTC, at least 1. */
export function secondsToUtcMidnight(now: Date): number;
```

`count` is the number of accepted entries after folding. Rejected entries are free. `day` is the UTC date
(`YYYY-MM-DD`) of `now`. The charge is a single upsert that adds and checks at once:

```sql
INSERT INTO package_usage (user_id, day, packages, calls)
SELECT ?1, ?2, ?3, 1 WHERE ?3 <= ?4
ON CONFLICT (user_id, day) DO UPDATE
  SET packages = packages + excluded.packages, calls = calls + 1
  WHERE package_usage.packages + excluded.packages <= ?4
RETURNING packages
```

- **A row comes back:** the call is charged.
- **No row:** the call would cross the limit, and none of it is charged. A plain read of today's row gives
  `remaining`; if that read fails, `remaining` is 0. The route answers 429
  `{ error: 'quota_exceeded', limit: 20000, remaining, retryAfter }`, with `Retry-After` set to
  `secondsToUtcMidnight(now)`.
- **D1 throws:** the route answers 503 `{ error: 'quota_unavailable' }` with `Retry-After: 30`. No lookup runs.
  The quota fails closed.
- **The lookup fails after a charge:** `refundQuota` runs in `waitUntil`
  (`UPDATE … SET packages = MAX(0, packages - ?3)`). A failed refund is logged as `packages_refund_failed`,
  with no values.

### 4. Lookup (`apps/api/src/lib/packages-lookup.ts`)

```ts
export const LOOKUP_CHUNK = 100;
export function loadPackageData(env: ReadEnv, names: Map<Ecosystem, string[]>): Promise<PackageData>;
```

1. **Affected ranges.** Take the distinct names per ecosystem, in chunks of 100. Each chunk is one statement,
   and every chunk goes in one `DB_ADVISORIES.batch()`. D1 allows at most 100 bound parameters per
   statement, so the names are bound as one JSON array:

   ```sql
   SELECT a.ecosystem, a.name, a.source, a.source_id, a.range_no, a.vuln_key, a.range_type,
          a.introduced, a.fixed, a.last_affected, a.versions,
          p.summary, p.severity, p.reviewed, p.url, p.published, p.modified
   FROM affected a
   JOIN package_advisories p ON p.source = a.source AND p.source_id = a.source_id
   WHERE a.ecosystem = ?1 AND a.name IN (SELECT value FROM json_each(?2)) AND p.status = 'active'
   ```

2. **Hot-set data and signals.** For the distinct `vuln_key`s found, use chunks of 100 and one batch per
   database. Run these at the same time (`Promise.all`), together with the licence read
   (`displayFor(env.SETTINGS, sourceIds)`):

   ```sql
   SELECT key, kind, title, cvss, cvss_source, epss, kev_added, ransomware, exploit_public
   FROM vulns WHERE key IN (SELECT value FROM json_each(?1))

   SELECT vuln_key, kind, source FROM signals
   WHERE vuln_key IN (SELECT value FROM json_each(?1))
     AND kind IN ('exploited_wild','public_exploit','poc','ransomware')
   ```

   `ransomware` signals are read too, because `rankPriority` takes a ransomware flag.

3. **Outside the hot set.** A `vuln_key` with no `vulns` row is an older record. It still matches; it just has
   no title, EPSS or KEV data.

4. **Malicious records.** A record is malicious when any of these holds: `source` is
   `openssf-malicious-packages`, `vuln_key` starts with `MAL-`, or `vulns.kind` is `'mal'`.

That is three D1 round trips, whatever the list size: advisories, then vulns and signals side by side. Every
statement is an index search; a test checks the query plans.

### 5. Matching, ranking and upgrade advice (`apps/api/src/lib/packages-match.ts`)

Pure code. Version rules come in as a dependency (`{ inRange, comparerFor }`, from `@ti/core/versions` by
default), so tests can pass a toy comparer.

**Covering a version.** `rowCovers(ecosystem, version, row)`:

- A non-`EXACT` row with `introduced = '0'` and no `fixed` or `last_affected` covers every version, without a
  comparer. Malicious-package records usually look like this.
- Every other row goes to `inRange`.

**Matching.** Licence filtering comes first (section 6): records from hidden sources are dropped before
matching. Then, for each non-private package, each record (`source`, `source_id`) is one of:

- **matched:** at least one of its rows covers the version;
- **uncertain:** none does, and at least one row returned `'unsupported'`;
- **clear:** otherwise.

Group the matched records by `vuln_key`; each group is one `CheckMatch`. A `vuln_key` with only uncertain
records goes into that package's `uncertain` entry, with `reason: 'version_rules_pending'`. A package can be
in both `results` and `uncertain`. A package with neither goes in `noRecord`. MTI never claims a match it
could not evaluate.

**Priority.** Each match gets `rankPriority` with:

| Input | From |
| ----- | ---- |
| `exploitedWild` | `vulns.kev_added` set, or a visible `exploited_wild` signal |
| `ransomware` | `vulns.ransomware = 1`, or a visible `ransomware` signal |
| `malicious` | any matched record is malicious (section 4) |
| `publicExploit` | `vulns.exploit_public = 1`, or a visible `public_exploit` signal |
| `poc` | a visible `poc` signal |
| `epss` | `vulns.epss` |
| `cvss` | `vulns.cvss` unless `cvss_source` is hidden; else the highest numeric `severity` (0–10) of a full-display record |
| `severityLabel` | the highest of `CRITICAL`, `HIGH`, `MODERATE`/`MEDIUM`, `LOW` among full-display `severity` values |

The rules are the shared ones in `rankPriority`:

- `fix_now`: exploited in the wild, used by ransomware, or malicious;
- `fix_soon`: public exploit code or a proof of concept, or EPSS of 0.1 or more;
- `plan`: CVSS 7.0 or more, or a HIGH or CRITICAL label when there is no score;
- `note`: everything else.

`signals` lists the true flags in this order: `malicious`, `exploited_wild`, `ransomware`, `public_exploit`,
`poc`. A package's priority is the highest of its matches.

Sort the matches by priority, then id, and keep the first 50 (`MAX_MATCHES_PER_PACKAGE`). `omitted` is the
number left out; priority is computed before the cut. Sort `results` by priority, then ecosystem, name and
version. `summary` counts packages per priority.

**`fixedIn`.** Fix versions come only from reviewed records (`package_advisories.reviewed = 1`) with full
display. Take the `fixed` of the row that covers the version. Ignore a value that fails the version grammar,
or that a comparer puts at or below the checked version. Several distinct values give the highest by the
comparer, or null when there is no comparer. A match with only unreviewed records has `fixedIn: null`.

**`upgradeTo`**, per package:

1. **Every match needs a fix.** If any match has `fixedIn: null`, `upgradeTo` is null. The note says no
   reviewed fix is listed for that id. If the match is malicious, it gets the malicious note instead.
2. **Pick the highest.** The candidate is the highest `fixedIn` across matches, by the comparer. With no
   comparer and more than one distinct value, `upgradeTo` is null, with a note.
3. **Check the candidate itself.** Run `rowCovers` for the candidate over every active row of that package.
   This covers every source, hidden sources and malicious records included: hidden records never appear in
   an answer, but they may stop a suggestion.
   - Any `true`: null, and the note says the version is listed as affected too.
   - Any `'unsupported'`: null, and the note says MTI can't check that version yet.
4. **Otherwise** `upgradeTo` is the candidate. The note names the source (its MTI display name), the record id
   and the record's `modified` date.
5. **Same package only.** `upgradeTo` is always a version of the package that was sent. No field names a
   different package as a replacement. A `fixed` value that looks like a name, a path, a URL or `name@version`
   fails the version grammar and is ignored.

**Note texts** are fixed. Their only slots are versions, record ids, MTI source names, dates and ecosystem
names:

- suggestion: "`<v>` fixes every match above, according to `<source>` (`<id>`, updated `<date>`). Confirm
  `<v>` exists in the registry and isn't brand new before installing it, and check it for breaking changes."
- no fix: "No reviewed fix is listed for `<id>`."
- malicious: "`<id>` marks this package as malicious. Remove it rather than upgrading, and treat machines that
  installed it as exposed."
- candidate affected: "`<v>` is listed as affected too, so no upgrade is suggested."
- can't check: "MTI can't yet check `<v>` against every listed range for `<ecosystem>`, so no upgrade is
  suggested."
- can't order: "MTI can't yet order `<ecosystem>` versions, so it can't pick one version that fixes every
  match."

**Private entries.** An entry marked `private: true` is matched only against visible malicious records, by
name and for any version.

- A hit adds `{ package, ids, reason: 'public_malicious_name' }` to `confusion`. This is a sign of a
  dependency-confusion attack.
- A private entry never goes in `results` or `uncertain`. Public advisories for the same name describe a
  different package. With no hit it goes in `noRecord`.

### 6. Licences and the answer (`apps/api/src/lib/packages-answer.ts`)

The licence rules are the ones `routes/entries.ts` applies, via `displayFor` and `creditsFor`.

- **Hidden** (`wait`, or a `SETTINGS` override): the source's records are dropped before matching. Its signals
  are ignored. `cvss` is null when `vulns.cvss_source` is hidden. A hidden source id appears nowhere in the
  answer.
- **Link-only:** the record can match. It shows only its id, source and URL. Its `summary`, `severity` and
  fix versions are neither shown nor used.
- **Full:** every field.
- **Hot-set fields:** `vulns.title`, `epss`, `kev_added`, `ransomware` and `exploit_public` are used the way
  `entries.ts` uses them.

Each `CheckMatch` field:

- **`url`:** the MTI entry page `<origin>/e/<id>` when a `vulns` row exists. Otherwise the first visible
  record URL starting with `https://`, by source id. Otherwise `<origin>/search?q=<id>`. `<origin>` is
  `SITE_ORIGIN`, else `https://mti.motiontic.com`.
- **`title`:** `vulns.title`, else null.
- **`summary`:** from the first full-display record (reviewed ones first, then by source id), else null.
- **`sources`:** the visible sources of the match's records and of the signals used.

The response's `credits` is `creditsFor` over every source in the answer, so the NVD notice appears when NVD
data is used. Text is returned as stored; the MCP server cleans it before it reaches an agent.

`asOf` is the request time. `checked` is the number of accepted entries; `matched` is the number of `results`.

`notes` are fixed strings, in this order:

1. Always: "No record means none in MTI as of asOf. It does not mean safe."
2. Always: "Reachability isn't checked: MTI doesn't know whether your code uses the affected part."
3. Always: "Fix versions come only from reviewed sources. Confirm a release exists and isn't brand new before
   installing it."
4. When `uncertain` isn't empty: "Some records couldn't be matched to a version yet. They are listed under
   uncertain, not as matches."
5. When an entry was marked private: "Packages marked private are checked only against public malicious
   packages with the same name."
6. Always: "Which sources MTI holds, and how fresh each one is: /sources on the MTI site."

### 7. Route (`apps/api/src/routes/packages.ts`)

```ts
export interface PackagesDeps { now?: () => Date; versions?: { inRange: typeof inRange; comparerFor: typeof comparerFor } }
export function createPackagesRoute(deps?: PackagesDeps): Hono<AppEnv>;
export default createPackagesRoute();   // index.ts stays as it is
```

`POST /v1/packages/check`:

1. **No-store first.** A small middleware sets `Cache-Control: no-store`, so every answer carries it, 401
   included.
2. **Sign-in.** `requireUser`. Web users come with a Clerk session. MCP users come with the signed identity,
   which mcp-seams already accepts for this route with `mti:read`. Nothing else is needed for access.
3. **Body.**
   - Over 1 MiB (checked on `content-length`, then on the bytes): 413 `{ error: 'body_too_large' }`.
   - Not JSON: 400 `{ error: 'invalid_body' }`.
   - Then `readCheckBody`: 400 `{ error: 'invalid_body' }` or 400 `{ error: 'too_many_packages', max: 1000 }`.
4. **Nothing accepted:** answer 200 with `rejected` and `notes` only. No quota charge and no D1 reads.
5. **Quota:** `chargeQuota`, then 429 or 503 as in section 3.
6. **Answer:** lookup, match, build. Any error here refunds the charge and answers 500
   `{ error: 'internal' }`, logging only the route and the error name, as `guarded()` does.
7. **Success:** 200 with the `CheckResponse`.

### 8. Logging and privacy

- **One line per call.** `logEvent('info', 'packages_check', …)` with only these fields:
  - `requestId` and `outcome` (`ok`, `all_rejected`, `quota_exceeded`, `quota_unavailable`, `failed`);
  - `checked`, `matched`, `rejected`, `uncertain`, `confusion`, `unknownNames`, and `ecosystems` (a count);
  - `ms`, `msQuota`, `msLookup`, `msMatch`.
- **`unknownNames`** counts accepted, non-private names with no `affected` row at all. It lets a later alert
  spot accounts that probe names MTI doesn't know. The answer itself never says whether MTI knows a name.
- **Never logged:** names, versions, purls, rejected values, record ids, upgrade targets, and zod or D1 error
  messages.
- **Nothing stored.** The only write is the usage counter.
- **No outbound calls.** No `fetch`, and no registry, OSV or deps.dev calls. The route reads only D1 and the
  `SETTINGS` KV.

### 9. Speed

The target is p95 under 1.5 s for 500 packages. The design keeps it to three D1 round trips plus one KV read
that runs alongside them.

Measure it on staging after merge:

1. Wait for staging to run main, and for the package data to be loaded there. Record the `affected` row count
   (`wrangler d1 execute ti_advisories_staging --remote --command "SELECT COUNT(*) FROM affected"`). If the
   table is empty, the measurement waits. If the staging deploy hasn't run yet, `pnpm preview` from an
   up-to-date main checkout serves the same code.
2. For the body, use 500 npm packages and versions from this repository's own `pnpm-lock.yaml`. That is public
   data, never a user's list. Build it with a one-off command and don't commit it.
3. Sign in as a staging test user and send the Clerk session token as `Authorization: Bearer`.
4. Make 3 warm-up calls, then 30 timed calls, one at a time, with `curl -w '%{time_total}'`. That is 16,500
   packages, inside one day's quota.
5. p95 is the 29th of the 30 sorted times. Post the times, the median, the p95, the row count and the
   server-side `ms` values from `wrangler tail` (the `packages_check` lines) on the merged PR. It passes when
   p95 is under 1.5 s.

## Tests

### Workers: `apps/api/test/packages-check.workers.test.ts`

**Setup.**

- Most cases use the test app from `account.workers.test.ts`: `createPackagesRoute(deps)` behind a middleware
  that sets `clerkAuth` from `x-test-user`.
- The log and MCP cases use `createApp(stubClerk)` from `launch.workers.test.ts`.
- `beforeEach` clears `affected`, `package_advisories`, `package_usage`, the test `vulns` and `signals` rows,
  and the `source:*` keys in `SETTINGS`.
- A `fetch` spy fails the test on any call.
- Helpers seed records, ranges, vulns and signals.
- Token-shaped test values are put together at runtime (for example `['ghp', '_', tail].join('')`), so no
  token-like literal is committed and secret scanners stay quiet.

**Cases.**

- **Access.**
  - Signed out: 401 with `no-store`.
  - Clerk session: 200.
  - A request signed with `signMcpAssertion` (scope `mti:read`, test env with `MCP_HMAC_SECRET` set): 200, and
    today's `package_usage` row belongs to the assertion's `sub`.
- **Ranking bands.** Each fixture ranks as listed. Real version rules apply, so fixtures use `EXACT` rows and
  all-versions rows:

  | Fixture | Priority |
  | ------- | -------- |
  | `vulns.kev_added` set | fix_now |
  | visible `exploited_wild` signal, no KEV | fix_now |
  | `vulns.ransomware = 1` | fix_now |
  | all-versions record from `openssf-malicious-packages` | fix_now |
  | `MAL-` id from the `osv` source | fix_now |
  | `exploited_wild` signal from a hidden source only, CVSS 5.0 | note |
  | `public_exploit` signal | fix_soon |
  | `vulns.exploit_public = 1` | fix_soon |
  | `poc` signal | fix_soon |
  | EPSS 0.10 | fix_soon |
  | EPSS 0.099 with CVSS 7.0 | plan |
  | no `vulns` row, record `severity` `HIGH` | plan |
  | CVSS 6.9 | note |
  | a record and nothing else | note |
  | one `note` match plus one `fix_now` match | fix_now, with matches in that order |

- **Malicious → fix_now.** An all-versions `MAL-` record gives fix_now with no comparer at all. `signals`
  includes `malicious`, `upgradeTo` is null and the note is the malicious one.
- **Rejections.**
  - One request holds an example of every reason. `rejected` equals the exact `{ index, reason }` list.
  - The response text contains none of the rejected values.
  - The valid entries in the same request are still answered.
- **Secrets.** Every row of the token table, `user:pass@` in a name, a JWT, 40 random base64 characters, 64
  random hex characters, and a purl with `?repository_url=https://u:p@host`: all are `looks_like_secret`.
  Every value in the must-accept corpus below is answered, not rejected.
- **Caps.**
  - 1,001 entries: 400 `too_many_packages`, and no usage row.
  - 1,000 entries: 200.
  - A body over 1 MiB: 413.
- **Quota edge** (`now` injected):
  - At 19,000 used, 1,000 more gives 200 and the row reads 20,000.
  - One more then gives 429 with `remaining: 0`. At 23:59:30Z, `Retry-After` and `retryAfter` are 30.
  - At 19,500 used, 501 more gives 429 with `remaining: 500`, and the row is unchanged.
  - Yesterday's row at 20,000 doesn't block today.
  - Two parallel calls of 400 at 19,500 used: exactly one gets 200.
  - Rejected entries aren't charged.
  - A `DB_USERS` whose `prepare` throws gives 503 `quota_unavailable`, and no `DB_ADVISORIES` statement runs.
  - A `DB_ADVISORIES` that throws gives 500, and the usage row goes back to its earlier value.
- **Upgrade advice** (toy integer comparer injected):
  - A reviewed range with `fixed: '5'` and the checked version `3` gives `upgradeTo: '5'`. The note holds the
    source's display name, the record id, the date and the confirm sentence.
  - An unreviewed record with `fixed: '9'` is never offered, and its match has `fixedIn: null`.
  - **The candidate is itself affected:** a malicious `EXACT ["5"]` record gives null and the "affected too"
    note. A second range with `introduced: '5'` and `fixed: '7'` gives the same.
  - A candidate check that returns `'unsupported'` gives null and the "can't check" note.
  - Two matches fixed in `5` and `7`, with `7` clear, give `7`.
  - No comparer and two distinct fixes give null and the "can't order" note.
  - A `fixed` of `other-pkg@1.0` is ignored.
  - In every answer, `upgradeTo` passes the version grammar and `package` equals the normalised input.
- **Licence hiding.**
  - `source:github-advisory-db` set to `hidden`: its only record no longer matches, so the package is in
    `noRecord`, and `github-advisory-db` appears nowhere in the response.
  - A hidden signal source doesn't raise priority.
  - A hidden `cvss_source` gives `cvss: null`.
  - `link` mode shows the id, URL and source only (`summary` and `fixedIn` are null, and severity doesn't
    count).
  - `credits` lists only visible sources.
- **Dependency confusion.**
  - A private entry whose name has a public malicious record lands in `confusion` with the ids, not in
    `results`.
  - The same entry without `private` gives fix_now in `results`.
  - A private entry whose name has only ordinary advisories goes in `noRecord`, with no match.
- **Uncertain path** (an `inRange` stub that returns `'unsupported'`):
  - The package is listed in `uncertain` with its ids and `version_rules_pending`, not in `noRecord`, and
    note 4 is present.
  - A package with one matched record and one uncertain record appears in both `results` and `uncertain`.
- **Headers and notes.**
  - Every answer has `Cache-Control: no-store`: 200, 400, 401, 413, 429, 500 and 503.
  - Every 200 has note 1, word for word.
- **Logs.**
  - Use the full app with spies on `console.log`, `warn` and `error`.
  - Make an ok call, a call with rejected secrets, a 429, a 503 and a 500, using canary names, versions, purls
    and record ids.
  - No captured line holds any of them, and every line is JSON.
  - Each call writes exactly one `packages_check` line, with only the fields in section 8.
- **Scale.**
  - Seed 3,000 `affected` rows (600 npm names, 5 rows each) with their records, then check 500 of those
    names. The counts are right.
  - `DB_ADVISORIES.batch` runs once with 5 statements; `vulns` and `signals` run one batch each.
- **Query plans.** `EXPLAIN QUERY PLAN` for the three lookup statements shows a `SEARCH` on each table's
  primary key, and no `SCAN` of `affected`, `vulns` or `signals`.
- **No outbound calls.** The `fetch` spy is never called anywhere in the file.

### Node: `apps/api/test/packages-input.test.ts` and `packages-match.test.ts`

- **Input.**
  - Every ecosystem's name and version grammar, with good and bad examples.
  - Steps 2–4 against both corpora.
  - NFKC: full-width `ｌｏｄａｓｈ` becomes `lodash`.
  - Duplicate folding after npm lower-casing, and the private flag carrying over.
  - The purl re-check after decoding: `%E2%80%8B` gives `bad_characters`.
- **Matching.**
  - `rowCovers` on all-versions rows.
  - The upgrade picker with a toy comparer.
  - Each note template.
  - `secondsToUtcMidnight`: 00:00:00Z gives 86,400, and 23:59:59.5Z gives 1.

**Must accept:**

- `actions/checkout` at `a5ac7e51b41094c92402da3b24376905380afc29`
- `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5` at `v5.7.0`
- `golang.org/x/net` at `v0.0.0-20231115185253-1b2c3d4e5f60`
- `org.springframework.boot:spring-boot-starter-web` at `3.2.0`
- `Microsoft.Extensions.DependencyInjection.Abstractions` at `8.0.0`
- PyPI `torch` at `2.1.0+cu121`, and `pypi-simple` at `1.4.0`
- npm `@typescript-eslint/eslint-plugin` at `6.13.2-alpha.0`, and `sk-utils` at `1.0.0`
- Debian `glibc` at `2.36-9+deb12u4`, and at `1:2.36-9`
- Red Hat `openssl` at `1:3.0.7-24.el9`
- RubyGems `nokogiri` at `1.15.4-x86_64-linux`
- SwiftURL `github.com/apple/swift-nio` at `2.62.0`
- `pkg:npm/left-pad@1.3.0?repository_url=https://registry.npmjs.org`

**Must reject:**

- every token-table prefix with a matching tail;
- `AKIA` plus 16 characters;
- a 40-character AWS-style secret key containing `/`;
- a three-part JWT;
- 40 random base64 characters;
- 64 random hex characters;
- `deploy:s3cr3t@registry` as a name;
- `https://evil.test/x` as a name and `git+https://host/x.git` as a version (both `looks_like_url`).

## Not in scope

- **Version comparers.** They land separately. Until then, ranges are reported under `uncertain`.
- **Loading** `affected` and `package_advisories`.
- **MCP formatting.** The `check_packages` MCP tool, cleaning untrusted text and shaping answer size belong
  to the MCP server.
- **Bigger inputs.** Lists over 1,000 packages, background jobs, and SBOM input.
- **Abuse detection.** Alerts on probing patterns, canary records, bot protection, and per-account caps on
  unknown names. A cap needs a new column, which belongs to a later change.
- **Guessing which packages are private** from scopes or naming. Only the explicit `private: true` counts.
- **Reachability analysis**, and a "report a wrong match" link.
- **Storage.** Inputs and answers are never stored.
- **A web page** for this route.
- **Platform changes.** Changes to `RL_USER` limits, the MCP route allow-list, migrations or Wrangler config.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass with the tests above. `pnpm typecheck` passes repo-wide.
2. `git diff --name-only main` lists only the paths in "What to build".
   `git diff main -- packages/core/src/packages.ts` only adds: the types and fields in section 1, the new
   reason literals, and `private` in the request schema. It removes nothing.
3. `rg -n "fetch\(" apps/api/src/routes/packages.ts apps/api/src/lib/packages-*.ts` finds nothing. The
   no-`fetch` lint check passes. In Workers tests, `fetch` is never called. Save the `rg` output.
4. Every fixture in the ranking table ranks as listed, including malicious → fix_now with no comparer.
5. Each rejection reason has a test. Every must-reject value is refused with the listed reason, and every
   must-accept value is answered. A rejected entry is `{ index, reason }` only, and no rejected value appears
   in any response body or log line.
6. Inputs with control, zero-width, bidi, Unicode Tag or variation-selector characters are refused as
   `bad_characters`. Full-width names are NFKC-normalised.
7. The quota holds at exactly 20,000 per user per UTC day:
   - one statement adds and checks;
   - an over-quota call is refused whole, with 429, `remaining` and the seconds to 00:00 UTC;
   - a D1 error gives 503 and runs no lookup;
   - a failed lookup refunds the charge.
8. `upgradeTo` comes only from reviewed records. It is null, with the right note, when:
   - any match has no reviewed fix;
   - the candidate is affected or malicious itself;
   - the candidate can't be checked;
   - versions can't be ordered.

   It is never another package. Each suggestion's note names the source, the record id and the date, and
   says to confirm the release exists and isn't brand new.
9. Licence rules match `entries.ts`:
   - hidden sources appear nowhere in an answer and don't count toward a match or a priority;
   - link-only sources show id, source and URL only;
   - `credits` lists only visible sources.
10. A private entry whose name has a public malicious record gets a `confusion` warning, and never appears in
    `results`.
11. When ranges can't be evaluated, the package is listed under `uncertain`, never as a match and never in
    `noRecord`.
12. Every response has `Cache-Control: no-store`. Every 200 includes the note "No record means none in MTI as
    of asOf. It does not mean safe."
13. Across the whole Workers test run, no log line holds a package name, version, purl, rejected value or
    record id. Each call writes one `packages_check` line with counts and timing only.
14. Web sessions and MCP identities with `mti:read` both get answers. Signed-out calls get 401.
15. Each lookup statement's query plan is an index search. A 500-package check of one ecosystem uses one
    advisories batch of 5 statements, plus one batch each for `vulns` and `signals`.
16. The PR states each platform fact it relies on, with a docs link:
    - D1's limit of 100 bound parameters per statement;
    - `json_each` in D1;
    - D1 `batch()`;
    - SQLite `INSERT … ON CONFLICT DO UPDATE … WHERE` with `RETURNING`.
17. After merge, the staging measurement in section 9 is posted on the PR. p95 for 500 packages is under 1.5 s.
    If staging has no package data yet, the PR says the measurement is still to come.

## Decisions added at review

- **OS packages:** OS rows are stored with their release, exactly as OSV writes them (`Debian:12`,
  `Ubuntu:22.04:LTS`, `Alpine:v3.20`).
  - Input accepts those keys, and maps the purl `distro` qualifier (`pkg:deb/debian/openssl@…?distro=debian-12`)
    to them.
  - A bare `Debian` or `Ubuntu` with no release is rejected with reason `bad_ecosystem` and a note asking for the
    release.
  - The lookup uses the full key.
- **`vuln_key`** in `affected` and `package_advisories` is the CVE the record names when it has one, else the
  record's own ID. Join it to `vulns` and `signals` on that.
- **Import path:** if `main` puts the version module at `packages/core/src/versions/index.ts`, import it as
  `@ti/core/versions/index`, or add a one-line `packages/core/src/versions.ts` re-export. This change may add
  that file.
- **Request shape:** the body is `{ packages: [...] }`, as assumed above.
