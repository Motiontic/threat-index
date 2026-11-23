# pattern-runtime: the seven pull patterns as generic, config-driven code

## Why

Every source is pulled with one of seven patterns (`docs/IMPLEMENTATION_PLAN.md` §4). The collector's step calls
`patternFor(source.pattern)`'s `check()`, then `fetch()`; today all seven throw `NotImplementedError`. This change
fills them in as generic code: URLs, query parameters, selectors, repository paths and CSV columns come from the
source's config, and shared HTTP behaviour (conditional GET, `Range`, `User-Agent`, `Retry-After`, pauses,
timeouts, error types) lives in one module. Other features are built at the same time and own their files: the
collector (`apps/collector/**`), loader (`apps/loader/**`, `packages/db/src/**`), E2B bridge (`e2b/**`), linker
(`packages/linker/**`) and web app (`apps/web/**`). This one touches `packages/patterns/**`, one optional
`SourceConfig` field with a new types file, and new fixture files.

## Current state (checked on main; *seams* marks what the seams change, merged first, adds)

| Area | Today |
| ---- | ----- |
| `packages/patterns/src/<name>.ts` | Seven stubs; `check()` and `fetch()` throw `NotImplementedError`. *seams*: `by-name.ts` maps each name to its module |
| `packages/patterns/src/types.ts` | `PatternContext` (`source`, `cursor`, `userAgent`, `fetch`, `signal?`; *seams*: `wait`, `log`, `now`), `RawItem { id; body: unknown }`, `PatternResult` (`items`, `receipt: Receipt \| null`, `nextCursor`, `more`, `heavy?`), `MAX_ITEMS_PER_STEP = 40`, an unused `conditionalGet()`. *seams*: `HeavyJobRequest` = `JobRequest` (`@ti/core/control`) |
| `packages/patterns` | Depends on `@ti/core`, `@ti/sources`, `fast-xml-parser` 5.12.1 (unused). `tsconfig.json` includes `src` only. No tests |
| `SourceConfig` (`packages/sources/src/registry.ts`) | Optional `heavy`, `urls`, `parser`, `rateLimit: { perMinute }`. Only `cisa-kev` sets any (`parser: 'kev'`) |
| Sources by pattern | git 11, changelist 8, since 10, fingerprint 6, feed 6, page 3, heavy 11. `epss` is `since` with `heavy: true`; `zdi` and `databreaches-net` are link-only feeds; `exploit-db` is on GitLab |
| `Cursor`, `Receipt` (`packages/core/src/types.ts`) | `Cursor { kind: 'commit' \| 'timestamp' \| 'etag' \| 'version'; value: string; etag?: string }`, stored in `ti_control.cursors` (`value TEXT`). `Receipt { source, runId, fetchedAt, contentType, body }` |
| `fixtures/`, parsers | Only `fixtures/cisa-kev/` (`sample.json`, `SOURCE.md`); `test/fixtures.ts` reads them in Node and workerd. The KEV parser's `parse()` takes a whole catalogue `{ catalogVersion, vulnerabilities: [...] }` |
| Workers tests | *seams*: one project file per app, listed in the root `vitest.workers.config.mts`. None covers `packages/patterns` |
| `apps/collector/wrangler.jsonc` | Compatibility date 2026-11-01, `nodejs_compat`, `USER_AGENT` with an ops contact, `GITHUB_TOKEN` and `NVD_API_KEY` named as secrets, `max_batch_size: 5` |

## What to build

### 1. Source settings: `pull`

New `packages/sources/src/pull.ts` holds the types; `registry.ts` gains only `pull?: PullConfig` and its import.
Set no values in `packages/sources/src/sources/`.

```ts
import type { JobRequest } from '@ti/core/control';
import type { CredentialName } from '@ti/core/types'; // from the shared contract: 'github' | 'nvd'
export interface PullConfig {
  git?: { repo: string; branch?: string; include: string[] };            // 'owner/name'; branch default 'main'
  changelist?: { listUrl: string; timeColumn: number; refColumn: number; itemUrl: string; rangeBytes?: number };
  since?: { url: string; startParam: string; endParam?: string; offsetParam: string; limitParam: string;
    itemsPath: string; idPath: string; totalPath?: string; maxWindowDays?: number; lookbackDays?: number;
    auth?: { header: string; credential: CredentialName } };
  fingerprint?: { url: string; format: 'json' | 'csv'; itemsPath?: string; key: string;
    version?: { bytes: number; pattern: string } };                       // regex; group 1 = version
  feed?: { url: string; order?: 'newest-first' | 'oldest-first' };
  page?: { url: string; item: string; key: string; order?: 'newest-first' | 'oldest-first';
    fields: Record<string, string | { selector: string; attr: string }> };
  heavy?: { url: string; version?: { url: string; pattern: string; bytes?: number } };
  jobKind?: JobRequest['kind'];                                           // for `heavy: true`; default 'big-file'
}
```

- Each pattern reads only its own block; without it, `check()` and `fetch()` throw `not-configured` (§2), so the
  collector can record `skipped` until that source's config lands. Dotted paths walk objects; CSV columns are
  zero-based; `include` takes globs (`*` within a segment, `**` across segments).
- `PatternContext` already has, from the shared contract, `credentials?` (absent = unauthenticated) and
  `runId?` (copied into `receipt.runId`, else `''`). Don't change `types.ts`, apart from adding optional fields
  if one proves necessary; say why in the PR.

### 2. Errors: `packages/patterns/src/errors.ts`

```ts
export type PatternErrorCode = 'rate-limited' | 'timeout' | 'network' | 'server'           // retryable
  | 'http' | 'too-large' | 'format' | 'not-configured' | 'request-budget' | 'runtime';    // permanent
export class PatternError extends Error {
  readonly name = 'PatternError';
  readonly retryable: boolean; readonly status?: number; readonly retryAfterSeconds?: number; // ≤ 3600
  constructor(message: string, readonly code: PatternErrorCode,
    opts?: { status?: number; retryAfterSeconds?: number; cause?: unknown });
}
```

The collector is built at the same time and may not import this, so keep plain fields it can duck-type. Messages
never contain credentials or bodies.

### 3. HTTP: `packages/patterns/src/http.ts`

`request(ctx, url, opts?)` is a pattern's only way to the network and calls only `ctx.fetch`. Options: `method`
(`GET`/`HEAD`), `accept`, `validator`, `range: { start, end }`, `auth: { credential, header, scheme? }`,
`maxBytes`, `timeoutMs`. Result: `{ url, status, notModified, headers, text, validator, truncated }`.

- Always sends `user-agent: ctx.userAgent`; an empty one is `runtime` (SEC requires a contact).
- **Validators**: the ETag, else `lm:<Last-Modified>` (`validatorOf(headers)`), sent back as `If-None-Match` or
  `If-Modified-Since`. 304 → `notModified: true`. **Range**: `Range: bytes=start-end`; a 200 that ignored it is
  read only to the range length, then the stream is cancelled (`truncated: true`).
- **Size**: at most `maxBytes` (default `MAX_BODY_BYTES` = 5 MiB), checked on `Content-Length` and while
  streaming → `too-large`, which patterns turn into a heavy request (§4).
- **Rate limits**: 429, 503, or 403 with `Retry-After` or `x-ratelimit-remaining: 0`. Wait = `Retry-After`
  (seconds or date), else `x-ratelimit-reset` − `ctx.now()`, else 60 s. Up to `MAX_INLINE_WAIT_MS` (10 s):
  `ctx.wait(ms)` (`scheduler.wait`, no CPU) and retry once; longer: `rate-limited` with `retryAfterSeconds`.
- **Pause**: with `source.rateLimit.perMinute`, requests run one at a time, `60000 / perMinute` ms apart via
  `ctx.wait`; otherwise at most `MAX_PARALLEL` (6) at once, the connections a Worker may have awaiting headers.
- **Timeouts**: `timeoutMs` (default 20 s) via an `AbortController` linked to `ctx.signal`, not
  `AbortSignal.any` → `timeout`. Other 5xx and 408 → `server`; a rejected fetch → `network`; other 4xx → `http`.
- **Budget**: at most `MAX_REQUESTS_PER_STEP` (60) per `ctx` (a `WeakMap` counter), then `request-budget`.
- **Credentials**: `auth` sends `ctx.credentials[credential]` only to the config's origin, with
  `redirect: 'manual'`; follow up to 3 redirects, dropping the credential if the origin changes.
- **Logs**: `ctx.log('http', { origin, path, status, bytes, ms })`, never query, headers, credentials or body.

### 4. Rules every pattern follows

- `check()` is cheap and changes nothing. `fetch()` never assumes `check()` ran; with nothing new it returns
  `items: []`, `receipt: null`, `more: false` and the cursor it got. Time comes only from `ctx.now()`.
- At most 40 items. `more: true` = call `fetch()` again once `nextCursor` is committed; a mid-run cursor makes
  `check()` say `changed` without a request. Cursor values are opaque outside their pattern (composites are JSON).
  `nextCursor.etag` is set only on the step that finishes (`more: false`).
- `receipt` = `buildReceipt(ctx, parts)` (`src/receipt.ts`): `application/x-ndjson`, one `{ url, status,
  contentType, body }` line per response the items came from; `null` with no items; no request headers.
- **Heavy hand-off**: no items, `receipt: null`, `more: false`; `nextCursor` is where the job's data ends, and the
  caller commits it when the job completes. Triggers: a null cursor on `git`, `changelist`, `since` (`first-load`:
  no history pulls in a Worker); `source.heavy` on another pattern (on a change, `kind: pull.jobKind ??
  'big-file'`, no item downloads); a response over `MAX_BODY_BYTES` (`big-file`, items before it returned first).
  `fingerprint`, `feed` and `page` are small by definition: their first run is done in the Worker, 40 per step.
- **Only config URLs**: never follow links found in items. Values put into a URL template are encoded per path
  segment, `..` is rejected, and the result must keep the template's origin.
- **Exploits and PoCs, metadata only**: `git` requests only files matching `include` with a data extension
  (`.json .csv .md .xml .yaml .yml .txt`); `.py`, `.rb`, `.c` and the like are never requested.
- **Link-only sources**: `feed` and `page` cut items to `{ id, title, date, link }` and the receipt holds those cut
  items, not the response. Other patterns throw `not-configured` for a `link` source.
- XML declaring `<!ENTITY` is rejected as `format` before parsing.

### 5. The seven patterns

Each keeps exporting `check(ctx)` and `fetch(ctx)` and also exports its item body type.

- **git** (GitHub only). `check`: `GET https://api.github.com/repos/{repo}/commits/{branch}` with
  `Accept: application/vnd.github.sha` and `If-None-Match: "<cursor sha>"`; 304 or same SHA → unchanged. `fetch`:
  compare `base...head`, keep allowed files (`copied`/`changed` = modified), download up to 40 from
  `https://raw.githubusercontent.com/{repo}/{head}/{path}` (not removed files). At GitHub's 300-file cap, narrow
  `head` to the first commit after `base` (`more` until the branch head); still capped → `big-file`. `diverged`,
  a 404 for `base`, or a null cursor → `first-load` with `url: https://github.com/{repo}/archive/{sha}.tar.gz`.
  `ctx.credentials.github` goes as `Authorization: Bearer` to `api.github.com` only. Without it, log once and run
  unauthenticated (60 an hour per IP, and Workers share egress IPs): expect `rate-limited` until a token is passed.
- **changelist**. `check`: `HEAD listUrl` with the validator. `fetch`: `Range` reads of `rangeBytes` (default
  65,536) through the newest-first CSV, carrying partial lines over, until a line at or before the cursor; none
  within `MAX_RANGE_READS` (4) → `big-file` (`listUrl`). Sort new lines oldest-first by `(Date.parse(time), ref)`
  (bad lines skipped and counted), take 40, fetch each from `itemUrl` with `{ref}` filled in; 404/410 →
  `text: null`.
- **since**. Window `[start, min(now, start + maxWindowDays)]`. `check`: same query, limit 1; `total > 0` (or any
  item without `totalPath`) → changed. `fetch`: one page of up to 40 from `offset`; a finished window moves the
  cursor to its end, with `more` if it was capped. Windows share a boundary, so a record may come twice
  (newer-wins writes make that harmless). Null cursor → `first-load` at now, unless `lookbackDays` is set.
- **fingerprint**. `check`: with `version`, a `Range: bytes=0-(bytes-1)` read and the regex vs the stored
  version; else `HEAD` with the validator. `fetch`: the whole file, split into entries (over
  `MAX_FINGERPRINT_ITEMS` = 5,000 → `big-file`), each hashed (32-bit FNV-1a of its JSON text, 8 hex); return
  entries whose key is new or hash changed, 40 at a time in file order. Removed keys just leave the cursor.
- **feed**. RSS 2.0, RSS 1.0 (RDF) and Atom via `fast-xml-parser`; key `guid`, Atom `id`, `rdf:about`, else
  `link`. `check`: conditional GET; 304 or newest key = cursor → unchanged. `fetch`: walk from the newest end
  (`order`) to the cursor's key and return the oldest 40 new items, oldest first; the cursor becomes the newest
  key returned. If the cursor's key is gone, all items are new and a gap warning is logged.
- **page**. `HTMLRewriter`: `item` starts a row; each `fields` selector fills it (text chunks joined, whitespace
  collapsed, or the attribute made absolute against `url`); rows without `key` are skipped. Otherwise as `feed`.
  Don't touch `HTMLRewriter` at module load (`by-name.ts` must still import in Node); missing → `runtime`.
- **heavy**. `check`: with `version`, a ranged GET of `version.url` (default 4,096 bytes) and the regex; else
  `HEAD url` and its validator; neither → `not-configured` (never an E2B job every run). `fetch`: the same check,
  then `heavy: { kind: pull.jobKind ?? 'big-file', sourceId, url, reason: '<old> → <new>' }`. Never parses.

| Pattern | `kind` | `value` settled | `value` mid-run | `etag` |
| ------- | ------ | --------------- | --------------- | ------ |
| git | `commit` | head SHA | `{"base","head","done","tip"}` (`tip` false if narrowed) | — |
| changelist | `timestamp` | `["<time>","<ref>"]` of the newest change returned | same | list validator |
| since | `timestamp` | end of the last finished window (ISO) | `{"start","end","offset"}` | — |
| fingerprint | `version` if configured, else `etag` | `{"v":"<version or validator>","h":{"<key>":"<hash>"}}` | `"v":null` | validator |
| feed, page | `version` | key of the newest item returned | same | validator |
| heavy | `version` if configured, else `etag` | the version or validator | — | validator |

| Pattern | `RawItem.id` | `RawItem.body` |
| ------- | ------------ | -------------- |
| git | path | `GitFile { path, status: 'added' \| 'modified' \| 'removed' \| 'renamed', previousPath?, text: string \| null }` |
| changelist | ref | `ChangeItem { ref, time, text: string \| null }` |
| since, fingerprint (JSON) | `idPath` / `key` value | the document with the array at `itemsPath` cut to this one entry, so a whole-document parser (today's `kev`) still works |
| fingerprint (CSV) | `key` value | `{ <header>: value }` |
| feed, page | key | the parsed item, or `{ <field>: string }`; link-only `{ id, title, date, link }` |

### 6. Tests and fixtures

- Node tests in `packages/patterns/test/*.test.ts` (add `test` to the package `tsconfig.json`). `test/helpers.ts`
  builds a context with a fake `fetch` (routes by method and URL, records requests, fails on any other request),
  a fixed `now`, a recording `wait` that resolves at once, and a recording `log`.
- `test/examples.ts` exports one `pull` block per worked example below, with real URLs. Tests use
  `{ ...SOURCE_BY_ID.get(id), pull: EXAMPLES[id] }`; each source's parser feature later copies its block over.

| Pattern | Worked example (`packages/sources/src/sources/`) | Fixtures (`fixtures/<source>/`) |
| ------- | ------------------------------------------------ | ------------------------------- |
| git | `cve-list.ts`: `CVEProject/cvelistV5`, `cves/**/*.json` | `pattern-compare.json`, `pattern-CVE-2025-3248.json` |
| changelist | `osv.ts`: `modified_id.csv` (`<time>,<ecosystem>/<id>`) | `pattern-modified_id.csv` (~20 lines), `pattern-record.json` |
| since | `nvd.ts`: CVE API 2.0, `lastModStartDate`, `apiKey` header | `pattern-page-0.json`, `pattern-page-1.json` |
| fingerprint | `cisa-kev.ts`: `catalogVersion` in the first 512 bytes | `sample.json` (exists), `pattern-catalog-v2.json` |
| feed | `cisa-advisories.ts`: CISA advisories RSS | `pattern-all.xml` |
| page | `cert-in.ts`: CERT-In advisory list | `pattern-list.html` |
| heavy | `cwe.ts`: `cwec_latest.xml.zip` | `pattern-head.json` (headers), `pattern-version.html` |

- Fixtures are hand-written, small, realistic. Names start with `pattern-` and notes (URL, date, licence) go in
  `fixtures/<source>/PATTERNS.md`, so nothing collides with fixtures other branches add to the same folders.
- Every pattern: unchanged (no items, cursor kept); a change from its fixture; over 40 new (40 and `more`, then
  the rest, cursors as in §5); a null cursor; a heavy hand-off; no `pull` block.
- `http`: user agent; validators; 304; 206 and an ignored-range 200; `Retry-After: 2` (one `wait(2000)`, then
  success) and `120` (`rate-limited`, no wait); GitHub 403 with `x-ratelimit-remaining: 0`; 503, 404, a rejected
  fetch, a timeout; an oversize body; the 61st request; the pause; a credential sent only to its origin, dropped
  on a cross-origin redirect, and absent from every log, error and receipt.
- `git` never requests a `.py` under `include`, and handles `diverged` and the 300-file cap; `changelist` breaks
  time ties by ref and hands off past 4 ranges; `since` caps the window, sends `apiKey` only to NVD, and hands off
  with `heavy: true`, `jobKind: 'epss-diff'`; `fingerprint` bodies parse with the KEV parser (import
  `../../parsers/src/kev` by path) and v2 returns only changed and new entries; `feed` reads inline Atom and RDF,
  warns on a lost cursor key, rejects `<!ENTITY`, and a link-only (`zdi`) item leaves no description in items or
  receipt; `page` in Node throws `runtime`; `heavy` without a validator → `not-configured`.
- `test/page.workers.test.ts`: fields, an absolute `href`, new rows only, the link-only cut. Its project file
  `packages/patterns/vitest.workers.mts` needs no bindings (`workerProject` on the collector's config with no
  databases, or plain `cloudflareTest` at the collector's date and flags). Don't edit the root config; if it misses
  this file, run `pnpm exec vitest run --config packages/patterns/vitest.workers.mts` and name the missing line.

### 7. Platform facts

Checked in Cloudflare's and GitHub's docs, 23 Nov 2026: subrequests per invocation 50 on Free, 10,000 by default
on Paid (this account), so 5 messages × 60 requests is safe; six connections awaiting headers; 128 MB memory;
`scheduler.wait(ms, { signal })` doesn't advance during CPU time when deployed; `HTMLRewriter` takes `E F`,
`E > F`, `:nth-child`, `:not` and attribute selectors, and splits text (`lastInTextNode`). GitHub compare lists
up to 300 files; a 304 is free only with `Authorization`. Re-check what you rely on, record any difference in the
PR, and say whether `toISOString()` dates suit NVD's documented format.

## Not in scope

- Calling the patterns: the collector step, committing cursors, writing receipts to R2, starting E2B jobs.
- `pull` values in `packages/sources/src/sources/*.ts` (they land with each source's parser); parsers; the linker.
- GitLab (`exploit-db`), CSAF ROLIE, Red Hat `deletions.csv`, SEC's filing-header request, CERT/CC month paging,
  Socrata `$where`, live endpoint checks: later, per source, as small additions to these patterns.
- Spacing requests across steps or sources (the pause holds within one step); adding a GitHub or NVD secret.
- Dependencies and `pnpm-lock.yaml`, migrations, Wrangler configs, `vitest.workers.config.mts`, the seams files.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process.
2. `pnpm test:workers` passes with the `page` tests, or the §6 fallback run passes and its output is saved.
3. No `NotImplementedError` is left in `packages/patterns/src`, and the `patternFor` test still passes.
4. `packages/patterns/src` never calls the global `fetch` or `Date.now()`, and waits only through `ctx.wait()`
   (`setTimeout` only arms request timeouts).
5. The §6 tests exist and pass with no network: the fake `fetch` fails any request it doesn't know.
6. `git diff --stat main` touches only `packages/patterns/**`, `packages/sources/src/pull.ts`, the `pull` field
   and import in `registry.ts`, and new `fixtures/*/pattern-*` and `fixtures/*/PATTERNS.md` files; `types.ts`
   only gains the two optional fields.
7. The PR flags `registry.ts` for human review and tells the collector to: pass `credentials` and `runId`; commit
   a heavy result's `nextCursor` only when its job completes; read `retryable`, `retryAfterSeconds` and `code`
   (`not-configured` → `skipped`) from thrown errors.
8. Proof saved: the `pnpm build` and Workers test output; a table of each pattern, its worked example and its
   tests; the §7 facts as re-checked.
