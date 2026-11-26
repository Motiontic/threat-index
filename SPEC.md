# mcp-seams: shared contracts and security plumbing for the MTI MCP server

## Why

MTI gets a remote MCP server: `https://mti.motiontic.com/mcp`, a new `ti-mcp` Worker on MCP spec 2026-07-28.
Several features are built next on separate branches at the same time: package data, version matching, the
package-check route and the MCP server itself, followed by skills, package watches, Tasks, SBOM checks, a report
view and change notices. Each owns its own files, but they meet at a few shared places: migrations, Wrangler
configs, the API's entry point and auth, the web Worker's entry point, the deploy script and the MCP tool list.

This change puts every meeting point on `main` once, as a migration, a type, a pure helper or a stub. It also
adds the security plumbing every later feature relies on:

- a signed MCP identity from `ti-mcp` to `ti-api`, so the user's token never leaves `ti-mcp`;
- an allow-list of API routes that accept that identity;
- per-user API rate limits for MCP traffic, which today arrives over a service binding with no IP and is not limited;
- a block list that refuses a user or client at once, even with an unexpired token;
- an `/mcp` forwarder with an off switch;
- release guards: a minimum package age, a production deploy guard and a no-`fetch` lint check.

It adds no MCP behaviour: `POST /mcp` answers "not ready".

## Current state (checked on main 00f7b56)

| Area | Today |
| ---- | ----- |
| `apps/api/src/lib/auth.ts` | `requireUser` sets `userId` from `getAuth(c)` only. `rate-limit.ts` (`signedInUser`, lines 42-48) and `request-context.ts` (lines 18-23) call `getAuth` themselves |
| `apps/api/src/lib/rate-limit.ts` | Signed in: `u:${userId}` on `RL_USER`. Otherwise `ip:…` on `RL_PUBLIC`. With no user and no IP (any service-binding call without a signed client IP) the request is **not limited** (lines 57-64) |
| `apps/api/src/lib/env.ts` | `Variables = { userId; requestId; limited? }`. No MCP fields. `SITE_ORIGIN` is set in wrangler but missing from `Bindings` |
| `apps/api/src/lib/delete-user.ts` | Deletes `watch`, `saved_searches`, `alert_queue`, `alerts_sent`, `users`. Called by `DELETE /v1/me` and the Clerk `user.deleted` webhook |
| `apps/api/src/index.ts` | `createApp(clerk)`: request context, security headers, health, then Clerk and `rateLimit` on `/v1/*`, then 17 route modules |
| `packages/core/src/sign.ts`, `edge.ts` | `hmac`, `constantTimeEqual`, `signRequest`/`verifyRequest` (±300 s), `signClientIp`/`verifiedClientIp` (±60 s) |
| `packages/db/migrations` | advisories `0001`; signals `0001`, `0002`; users `0001`–`0003`. `changes.kind` has a `CHECK` list of six kinds (signals `0001`, line 11) |
| `ChangeKind` | Declared in `packages/linker/src/detect.ts:32-38`, listed in `packages/linker/src/tables.ts:112-119` (`CHANGE_KINDS`), and checked against the migration in `packages/linker/src/schema.test.ts:106` |
| Linker | Writes `advisories` rows only for hot-set records (`link.ts:326`), so `advisories` can't hold data for every package advisory |
| `apps/web/workers/app.ts` | Redirect, then the per-IP page limit, then React Router. No path forwarding. Env types are hand-written in `apps/web/app/env.d.ts`. Tests: `apps/web/test/worker.test.ts`, `launch.test.ts` |
| `apps/notify/wrangler.jsonc` | Binds `DB_SIGNALS`, `DB_USERS`, `DB_VULNS`, `DB_WORLD`; no `DB_ADVISORIES` |
| `scripts/deploy.mjs` | `DEPLOY_ORDER = ['loader','notify','api','collector','web']`. An app missing from that list is never deployed. No check of the git state |
| Durable Objects | None anywhere |
| pnpm | `packageManager: pnpm@10.10.0`; no `minimumReleaseAge` |

## What to build

### 1. Migrations (new files only; never edit an applied one)

`packages/db/migrations/advisories/0002_package_data.sql`:

```sql
-- One row per source record that names affected packages, for every year (not only the hot set).
CREATE TABLE package_advisories (
  source TEXT NOT NULL, source_id TEXT NOT NULL,
  vuln_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','withdrawn','rejected')),
  summary TEXT,                         -- plain text, at most 300 characters, as the source wrote it
  severity TEXT,                        -- CVSS base score ("9.8") or the source's label ("HIGH")
  reviewed INTEGER NOT NULL DEFAULT 0,  -- 1 when fix versions come from the ecosystem's own database or a reviewed advisory
  url TEXT, published TEXT, modified TEXT NOT NULL,
  PRIMARY KEY (source, source_id)
) WITHOUT ROWID;
CREATE INDEX package_advisories_by_vuln ON package_advisories (vuln_key);

-- One row per affected range (or exact-version list) in such a record.
CREATE TABLE affected (
  ecosystem TEXT NOT NULL,              -- canonical OSV name: npm, PyPI, Go, Maven, crates.io, ...
  name TEXT NOT NULL,                   -- normalised with @ti/core/packages normaliseName
  source TEXT NOT NULL, source_id TEXT NOT NULL,
  range_no INTEGER NOT NULL,            -- position of the range within the record, from 0
  vuln_key TEXT NOT NULL,
  range_type TEXT NOT NULL CHECK (range_type IN ('SEMVER','ECOSYSTEM','EXACT')),
  introduced TEXT NOT NULL DEFAULT '0',
  fixed TEXT, last_affected TEXT,
  versions TEXT,                        -- JSON array when range_type = 'EXACT'
  PRIMARY KEY (ecosystem, name, source, source_id, range_no)
) WITHOUT ROWID;
CREATE INDEX affected_by_record ON affected (source, source_id);
CREATE INDEX affected_by_vuln ON affected (vuln_key);
```

`packages/db/migrations/users/0004_mcp.sql`:

```sql
CREATE TABLE watch_packages (
  user_id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  created_at TEXT NOT NULL, alerts_on INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id, ecosystem, name)
) WITHOUT ROWID;
CREATE INDEX watch_packages_by_package ON watch_packages (ecosystem, name);

CREATE TABLE package_usage (
  user_id TEXT NOT NULL, day TEXT NOT NULL,          -- day = YYYY-MM-DD (UTC)
  packages INTEGER NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
) WITHOUT ROWID;

-- Users and OAuth clients refused on every MCP request, even with an unexpired token.
CREATE TABLE mcp_blocks (
  kind TEXT NOT NULL CHECK (kind IN ('user','client')),
  id TEXT NOT NULL,                                  -- Clerk user ID, or OAuth client_id
  reason TEXT NOT NULL CHECK (reason IN ('deleted','abuse','security','request')),
  created_at TEXT NOT NULL, expires_at TEXT,         -- NULL = until removed
  PRIMARY KEY (kind, id)
) WITHOUT ROWID;
```

`packages/db/migrations/signals/0003_change_kinds.sql` rebuilds `changes` so its `CHECK` list also allows
`new_advisory` (SQLite can't alter a `CHECK`):

```sql
CREATE TABLE changes_new (
  id TEXT PRIMARY KEY, entity_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('newly_exploited','public_exploit','epss_band','fix_released','cvss_change','breach_notice','new_advisory')),
  old TEXT, new TEXT, at TEXT NOT NULL, source TEXT
) WITHOUT ROWID;
INSERT INTO changes_new (id, entity_key, kind, old, new, at, source)
  SELECT id, entity_key, kind, old, new, at, source FROM changes;
DROP TABLE changes;
ALTER TABLE changes_new RENAME TO changes;
CREATE INDEX changes_by_time ON changes (at);
```

Update the matching code in the same change:

- Drizzle schemas in `packages/db/src/schema/{advisories,users}.ts`, so `schema.workers.test.ts` still passes.
- `ChangeKind` in `packages/linker/src/detect.ts` and `CHANGE_KINDS` in `tables.ts` gain `new_advisory`, so `schema.test.ts:106` still passes. Nothing emits it yet.
- `describeChange` and `shortChange` in `apps/notify/src/render.ts` get a `new_advisory` case ("New advisory"). Its matching comes later.
- `CHANGE_LABELS` in `apps/web/app/routes/home.tsx` gets the same label.
- `users.alert_triggers` defaults stay as they are.

`ti_users` tables get rule `'none'` in `packages/db/src/table-info.ts`, like the other user tables. The new
advisories tables get the default upsert rule.

### 2. Package contracts: `packages/core/src/packages.ts`

Pure code, no dependencies beyond zod. It is used by the API, the MCP Worker, the linker and tests.

```ts
export const ECOSYSTEMS = ['npm','PyPI','Go','Maven','crates.io','RubyGems','NuGet','Packagist','Hex','Pub',
  'SwiftURL','GitHub Actions','Debian','Ubuntu','Alpine','Red Hat'] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];
/** Lower-cased aliases and purl types → canonical name ("pypi" → "PyPI", "cargo" → "crates.io", "golang" → "Go", "gem" → "RubyGems", "composer" → "Packagist", "deb" needs the distro qualifier). */
export function canonicalEcosystem(raw: string): Ecosystem | null;
/** Per-ecosystem name rules: npm lower-case (scope kept); PyPI PEP 503 ([-_.]+ → "-", lower-case);
 *  crates.io lower-case with "_" → "-"; NuGet, Packagist, Hex, Pub lower-case; Go, Maven (group:artifact),
 *  RubyGems, SwiftURL unchanged. Returns null when the name can't be valid for that ecosystem. */
export function normaliseName(ecosystem: Ecosystem, name: string): string | null;
export interface PackageRef { ecosystem: Ecosystem; name: string; version: string }
/** Parses `pkg:<type>/<namespace>/<name>@<version>` (percent-decoded). Ignores qualifiers such as
 *  repository_url and download_url entirely: they are never returned and never fetched. */
export function parsePurl(purl: string): { ok: true; ref: PackageRef } | { ok: false; reason: string };
export type Priority = 'fix_now' | 'fix_soon' | 'plan' | 'note';
export interface PriorityInput {
  exploitedWild: boolean; ransomware: boolean; malicious: boolean;
  publicExploit: boolean; poc: boolean; epss: number | null;
  cvss: number | null; severityLabel: string | null;
}
/** fix_now: exploited, ransomware or malicious. fix_soon: public exploit or PoC, or EPSS >= 0.1.
 *  plan: CVSS >= 7, or label HIGH/CRITICAL when there is no score. note: everything else. */
export function rankPriority(i: PriorityInput): Priority;
```

Also export the request and answer types of `POST /v1/packages/check` (`CheckRequest`, `CheckMatch`,
`CheckResult`, `CheckResponse`, `RejectedEntry`) exactly as below, with zod schemas for the request:

```ts
export const MAX_CHECK_PACKAGES = 1000;
export interface RejectedEntry { index: number; reason: 'bad_ecosystem' | 'bad_name' | 'bad_version' | 'bad_purl' | 'looks_like_secret' | 'duplicate' }
export interface CheckMatch { id: string; title: string | null; fixedIn: string | null; signals: string[];
  cvss: number | null; epss: number | null; url: string; sources: string[] }
export interface CheckResult { package: PackageRef; priority: Priority; upgradeTo: string | null;
  upgradeNote: string | null; matches: CheckMatch[] }
export interface CheckResponse { asOf: string; checked: number; matched: number;
  summary: Record<Priority, number>; results: CheckResult[]; noRecord: PackageRef[];
  rejected: RejectedEntry[]; notes: string[] }
```

Rejected entries carry an index and a reason only, never the value that was sent.

### 3. Version contract: `packages/core/src/versions/index.ts`

```ts
export interface Comparer { valid(v: string): boolean; compare(a: string, b: string): number }
/** Returns null for every ecosystem in this change; comparers arrive in their own files later. */
export function comparerFor(ecosystem: Ecosystem): Comparer | null;
export interface RangeRow { range_type: 'SEMVER' | 'ECOSYSTEM' | 'EXACT'; introduced: string;
  fixed: string | null; last_affected: string | null; versions: string | null }
/** EXACT rows match by string equality. Other rows use the OSV evaluation rules (introduced, fixed,
 *  last_affected; "0" = from the start) with the comparer, or return 'unsupported' when there is none. */
export function inRange(ecosystem: Ecosystem, version: string, row: RangeRow): boolean | 'unsupported';
```

Test the range walk with a toy integer comparer, and test that every ecosystem returns `'unsupported'` for
ranges today.

### 4. Signed MCP identity: `packages/core/src/mcp-user.ts`

`ti-mcp` checks the user's OAuth token itself, then calls `ti-api` over the service binding. It never forwards
the token. Instead it sends a signed assertion:

```ts
export const MCP_HEADERS = { sub: 'x-ti-mcp-sub', scopes: 'x-ti-mcp-scopes', client: 'x-ti-mcp-client',
  ts: 'x-ti-mcp-ts', sig: 'x-ti-mcp-sig' } as const;
export const MCP_SKEW_SECONDS = 60;
export const MCP_SCOPES = ['mti:read', 'mti:watch'] as const;
export interface McpIdentity { sub: string; scopes: string[]; clientId: string }
/** hex(HMAC-SHA256(secret, "mcp-assertion/v1\naud=ti-api\n" + [sub, sortedScopes.join(' '), clientId,
 *  requestId, METHOD, pathWithQuery, sha256hex(body), ts].join('\n'))). */
export function signMcpAssertion(secret: string, id: McpIdentity, req: { requestId: string; method: string;
  pathWithQuery: string; body: ArrayBuffer | null }, ts: number): Promise<Record<string, string>>;
/** Tries each secret (current, then next, for rotation). Fails closed: missing header, bad format
 *  (sub /^user_[A-Za-z0-9]{10,64}$/, clientId at most 512 printable characters, scopes ⊆ MCP_SCOPES),
 *  skew over 60 s, or a signature that matches no secret. */
export function verifyMcpAssertion(secrets: (string | undefined)[], headers: Headers, req: { requestId: string;
  method: string; pathWithQuery: string; body: ArrayBuffer | null }, now?: Date): Promise<McpIdentity | null>;
```

Tests cover these cases: a good assertion; a wrong secret; the next secret during rotation; an old or future
timestamp; a changed body, path, query, method or request ID; scopes out of order (still valid); an unknown
scope; a malformed `sub`.

### 5. ti-api: MCP identity, route allow-list, limits and block list

- **`lib/env.ts`**:
  - Add `MCP_HMAC_SECRET?: string`, `MCP_HMAC_SECRET_NEXT?: string` and `SITE_ORIGIN?: string` to `Bindings`.
  - Add `mcp?: McpIdentity` to `Variables`.
- **`lib/auth.ts`**: add `currentUserId(c)`, which returns `c.get('mcp')?.sub` or else `getAuth(c)?.userId`.
  `requireUser`, `rate-limit.ts` (`signedInUser`) and `request-context.ts` all use it. That way MCP calls are
  limited per user on `RL_USER` and logged with their user. Pin the Clerk middleware's token type with
  `clerkMiddleware({ acceptsToken: 'session_token' })`, so an OAuth access token sent straight to the API never
  counts as signed in.
- **New `lib/mcp-identity.ts`**, middleware `mcpIdentity`, mounted on `/v1/*` **before** the Clerk middleware:
  - **No `x-ti-mcp-*` header:** do nothing (web and browser traffic is unchanged).
  - **An MCP header plus an `Authorization` header or a `Cookie`:** 400 `{error:'ambiguous_auth'}`.
  - **Verify:** read the body once (`c.req.raw.clone().arrayBuffer()`) and call `verifyMcpAssertion` with both secrets. On failure: 401 `{error:'bad_mcp_assertion'}`. Never fall through to Clerk.
  - **Route allow-list:** the method and route must be on the list `MCP_ROUTES`, each entry with the scope it needs:
    - `GET /v1/search`, `/v1/entries/:id`, `/v1/home`, `/v1/breaches`, `/v1/breaches/:key`, `/v1/incidents`, `/v1/incidents/:source/:id`, `/v1/techniques/:id`, `/v1/sources`: `mti:read`;
    - `POST /v1/packages/check`: `mti:read`;
    - `POST /v1/deep-query`, `GET /v1/deep-query/:id`, `DELETE /v1/deep-query/:id`: `mti:read`;
    - `GET /v1/me`, `GET /v1/me/watch`, `GET /v1/me/watch/packages`, `GET /v1/me/changes`: `mti:read`;
    - `PUT`/`DELETE /v1/me/watch/:id` and `PUT`/`DELETE /v1/me/watch/packages/:ecosystem/:name`: `mti:watch`.
    - Anything else (admin, internal jobs, webhooks, `DELETE /v1/me`, saved searches) gets 403 `{error:'not_allowed_for_mcp'}`, even for a user in `ADMIN_USER_IDS`.
  - **Missing scope:** 403 `{error:'insufficient_scope', scope:'mti:watch'}`.
  - **Block list:** `SELECT 1 FROM mcp_blocks WHERE ((kind='user' AND id=?1) OR (kind='client' AND id=?2)) AND (expires_at IS NULL OR expires_at > ?3)`. A hit gets 403 `{error:'blocked'}`.
  - **On success:** `c.set('mcp', identity)`.
- **Admin rights:** `ADMIN_USER_IDS` checks (`admin-ops` and anything else that reads it) must ignore an MCP identity.
- **New stub route modules,** mounted once in `index.ts`. Each runs `requireUser` before answering 501 through `lib/not-implemented.ts`:
  - `routes/packages.ts`: `POST /v1/packages/check`
  - `routes/watch-packages.ts`: `GET /v1/me/watch/packages`, `PUT` and `DELETE /v1/me/watch/packages/:ecosystem/:name`
  - `routes/me-changes.ts`: `GET /v1/me/changes`
  - `DELETE /v1/deep-query/:id` in `routes/deep-query.ts`, a 501 stub
- **`lib/delete-user.ts`:** also delete from `watch_packages` and `package_usage`, and insert
  `mcp_blocks (kind 'user', reason 'deleted', expires_at = now + 30 days)` in the same batch. Update the doc comment.

### 6. The `apps/mcp` Worker (skeleton)

- **`package.json`** (`@ti/mcp`):
  - Exact versions: `@modelcontextprotocol/server` `2.4.0`, `@modelcontextprotocol/core` `2.4.0`, `@clerk/backend` `3.31.4`.
  - `zod` and `@ti/core` as the API has them.
  - This is the only package change in this PR besides the pnpm version (section 9).
- **`wrangler.jsonc`** (production at the top level, `env.staging` below):
  - `name: ti-mcp`, `main: src/index.ts`, the API's compatibility date and flags, `workers_dev: false`, `preview_urls: false`, no `routes`. It is reachable only through `ti-web`.
  - `services`: `API` → `ti-api` (`ti-api-staging`).
  - `kv_namespaces`: `SETTINGS` (`${TI_SETTINGS_KV_ID}`, staging `${TI_SETTINGS_KV_ID_STAGING}`), for tool off-switches under `mcp:tool:<name>:off`.
  - `durable_objects`: binding `MCP_TASKS`, class `McpTask`, plus `migrations: [{ tag: 'v1', new_sqlite_classes: ['McpTask'] }]`.
  - `ratelimits`: `RL_MCP` (60 per 60 s, namespace `7105` / `7205`) and `RL_MCP_ANON` (120 per 60 s, `7106` / `7206`).
  - `vars`: `TI_ENV`, `MCP_RESOURCE_URL` (`https://mti.motiontic.com/mcp`; staging `${TI_APP_URL_STAGING}/mcp`), `CLERK_ISSUER` (`${TI_CLERK_ISSUER}` / `${TI_CLERK_ISSUER_STAGING}`), `MCP_ALLOWED_ORIGINS` (`""`).
  - Secrets: `MCP_HMAC_SECRET`, `MCP_HMAC_SECRET_NEXT`. Check that `scripts/wrangler-config.mjs` fills a placeholder inside a longer string; if it can't, add a `TI_MCP_RESOURCE_URL_STAGING` variable instead.
- **`src/index.ts`**, the fetch handler. Every response gets the API's security headers (`API_SECURITY_HEADERS`), `Cache-Control: no-store` and an `x-request-id`:
  - `POST /mcp` → 503 `{"jsonrpc":"2.0","id":null,"error":{"code":-31001,"message":"not_ready"}}` (an application code outside the reserved −32768…−32000 range);
  - `GET` or `DELETE /mcp` → 405 with `Allow: POST`;
  - `/.well-known/oauth-protected-resource/mcp` and `/mcp/server-card` → 404 for now;
  - anything else → 404.
- **`src/api.ts`**: `callApi(env, { method, path, body, identity, requestId })` builds a fresh `Request` for `https://ti-api.internal`, adds the signed assertion and `x-request-id`, and calls `env.API.fetch`. It never copies the client's headers. It is the only file in `apps/mcp` that calls `fetch`.
- **`src/tools/index.ts`**: `TOOL_ORDER`, the fixed list
  `mti_check_packages, mti_check_sbom, mti_get_entry, mti_search, mti_latest_threats, mti_search_breaches,
  mti_search_incidents, mti_get_technique, mti_list_sources, mti_watch_add, mti_watch_remove, mti_watch_list,
  mti_deep_query`. Each has a stub file under `src/tools/` exporting `{ name, enabled: false }`.
- **`src/ext/{skills,tasks,listen,apps,uploads}.ts`**: each exports a no-op `register()`. `src/tasks/mcp-task.ts` exports a `McpTask` Durable Object class whose methods throw `NotImplementedError`.
- **Tests:**
  - `apps/mcp/vitest.workers.mts`, using `workerProject`. Replace the `API` service binding with an in-test handler (`miniflare.serviceBindings`) so tests don't need `ti-api`.
  - Workers tests for every route above, and for `callApi`: the assertion verifies on the API side, the body hash matches, and no client header leaks.
  - `apps/mcp/.dev.vars.example` with the secret names.

### 7. ti-web: forward `/mcp` with an off switch

In `workers/app.ts`, before the redirect and the page limit: if the path is `/mcp`, starts with `/mcp/`, or is
`/.well-known/oauth-protected-resource` (or starts with it plus `/`), then:

- if `env.MCP_ENABLED !== '1'`, answer 404 JSON `{error:'not_found'}` with the base security headers;
- otherwise forward to `env.MCP.fetch(new Request(request, { headers }))`, where `headers` is a copy of the
  request headers with `Cookie` and `x-ti-mcp-*` removed, and return the response unchanged (no page headers,
  no `noindex` logic).

Changes to config and tests:

- `wrangler.jsonc`: `services` adds `MCP` → `ti-mcp` (`ti-mcp-staging`). `vars.MCP_ENABLED` is `"0"` in production and `"1"` in staging.
- `app/env.d.ts`: add `MCP: Fetcher; MCP_ENABLED?: string`.
- Tests in `apps/web/test/worker.test.ts`:
  - forwarding;
  - the cookie is stripped;
  - incoming `x-ti-mcp-*` headers are stripped;
  - 404 when switched off;
  - `/mcpx` and `/mcp-docs` are not forwarded;
  - the page limiter doesn't count forwarded calls.

### 8. Other Workers and scripts

- **`apps/notify/wrangler.jsonc`:** add `DB_ADVISORIES` (`ti_advisories`, staging `ti_advisories_staging`); `src/env.ts` gets the type. Nothing reads it yet.
- **`scripts/deploy.mjs`:**
  - `DEPLOY_ORDER = ['loader','notify','api','collector','mcp','web']`.
  - A production guard that refuses unless the working tree is clean, `HEAD` is on `origin/main`, and nothing is unpushed. It prints why, and `--allow-dirty` is not offered.
- **`scripts/smoke-staging.mjs`:** add `web /mcp` (GET → 405) and `web /mcp/server-card` (→ 404 for now). Each gets the usual security-header checks plus "no `Set-Cookie`".
- **New `scripts/check-no-fetch.mjs`** (run by `pnpm lint`): fails when `fetch(` appears in `apps/mcp/src` outside `src/api.ts`, or in `apps/api/src` outside the files that use it today (list them in the script). It blocks URL fetching from request paths.

### 9. Release guards and review rules

- **pnpm:** set `packageManager` to `pnpm@10.34.9`. Add `minimumReleaseAge: 10080` (7 days) to `pnpm-workspace.yaml`, so a dependency published less than a week ago can't be installed. Regenerate `pnpm-lock.yaml` with no version changes other than the new `apps/mcp` dependencies.
- **`loops.json` `sensitivePaths`:** add `apps/mcp/src/**`, `apps/mcp/skills/**`, `apps/mcp/ui/**`, `packages/core/src/mcp-user*`, `packages/core/src/packages*`, `apps/api/src/lib/mcp-*`, `apps/api/src/lib/auth*`, `apps/web/workers/**` and `scripts/deploy*`.
- **`REVIEW.md`:** add an "MCP" section:
  - the user's token never leaves `ti-mcp`;
  - every source-derived string is cleaned before it reaches an agent;
  - nothing logs tool arguments, package lists or tokens;
  - tool descriptions are fixed text with no instructions to the model;
  - a new API route used by MCP needs an entry in `MCP_ROUTES` with its scope.
- **`SECURITY.md`:** the scope covers the MCP server at `/mcp`.
- **`security.txt`:** add `apps/web/public/.well-known/security.txt`, with `Contact:` set to the repository's private vulnerability-report URL, `Policy:` pointing to SECURITY.md, `Expires:` one year out and `Preferred-Languages: en`.

## Not in scope

- Any MCP protocol handling, OAuth token checks, tools, skills, Tasks, report view or change notices. `/mcp` answers "not ready".
- Writing `affected` or `package_advisories` rows. Emitting `new_advisory` changes.
- Version comparers.
- The logic of the package-check route.
- Creating Cloudflare resources. KV, the Durable Object namespace and rate limits come with the deploy. Secrets are set outside this change.
- Switching MCP on in production (`MCP_ENABLED` stays `"0"`).

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass. The new `apps/mcp` Workers project is picked up by the root config.
2. All three migrations apply on a fresh local D1, and `schema.workers.test.ts` passes. A Workers test applies signals `0001`–`0002`, inserts rows into `changes`, applies `0003`, and finds the same rows, plus one `new_advisory` row it can now insert.
3. `@ti/core/packages`, `@ti/core/versions` and `@ti/core/mcp-user` exist with the exports above and unit tests: `rankPriority` for every band, `normaliseName` per ecosystem, `parsePurl` (including that qualifiers are dropped), the range walk, and every signing case in section 4.
4. ti-api Workers tests show:
   - a signed MCP call to an allowed route succeeds as that user and is rate-limited on `u:<sub>`;
   - the same call to `/v1/admin/ops`, `/internal/jobs/x` or `DELETE /v1/me` gets 403 `not_allowed_for_mcp`, even for an admin user;
   - `mti:read` alone on a watch write gets 403 `insufficient_scope`;
   - a changed body, an old timestamp or a wrong secret gets 401;
   - an MCP header with a cookie or `Authorization` gets 400;
   - a blocked user or client gets 403 `blocked`;
   - `deleteUserData` removes the new rows and leaves a 30-day block;
   - web and session behaviour is unchanged (the existing tests pass untouched).
5. ti-mcp Workers tests show the 405, 503, 404 and header behaviour, and that `callApi` sends a verifiable assertion with no client headers.
6. ti-web tests show forwarding, cookie and `x-ti-mcp-*` stripping, the off switch, and no forwarding of look-alike paths.
7. `node scripts/deploy.mjs production` exits with an explanation on a dirty tree or an unpushed commit, without running wrangler.
8. `pnpm lint` fails on a planted `fetch(` in `apps/mcp/src/tools/` (shown in a test of the check script).
9. The only dependency changes are the `apps/mcp` packages and the pnpm version, and `pnpm install --frozen-lockfile` passes.
10. No secret or account ID is added to the repo. Wrangler configs use `${VAR}` placeholders only.
