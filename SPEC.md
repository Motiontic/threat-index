# account-api: profile, alert settings, watchlist, saved searches and account deletion for signed-in users

## Why

The signed-in part of the API is mostly stubs. `GET/PATCH/DELETE /v1/me` and the saved-search routes return
501, the watchlist returns raw snake_case rows without titles and has no cap, and the Clerk webhook can lose
a `user.deleted` event if the delete fails after the event was recorded. The account pages in the web app are
built next, against the types this change adds. This change builds `docs/IMPLEMENTATION_PLAN.md` §8 (the
`/v1/me*` routes) and the personal-data rules in §11: `DELETE /v1/me` and Clerk's `user.deleted` both remove
every row we hold for the user.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/me.ts` | `GET`, `PATCH`, `DELETE /v1/me`: `requireUser` + `notImplemented` (501) |
| `routes/saved-searches.ts` | `GET`, `POST /v1/me/saved-searches`, `DELETE /v1/me/saved-searches/:id`: `requireUser` + 501 |
| `routes/watch.ts` | `GET` returns `{ watch: [{ entry_key, alerts_on, created_at }] }`; `PUT /:id` upserts `normaliseId(id)` without checking the entry exists, no cap, unparsable body → alerts on; `DELETE /:id` deletes, always `{ ok: true }` |
| `routes/webhooks-clerk.ts` | `verifySvix` (throws without a secret → 400). Inserts the `svix-id` into `webhook_events` **before** handling; a later failure makes the retry look like a duplicate. `user.created/updated` upsert `users(id, email, name, created_at, digest_weekday)`; `user.deleted` calls `deleteUserData` |
| `lib/delete-user.ts` | `deleteUserData(db, userId)`: one batch deleting from `watch`, `saved_searches`, `alert_queue`, `alerts_sent`, then `users` |
| `lib/auth.ts` | `requireUser` reads `getAuth(c).userId` (never `orgId`), sets `c.var.userId`, else 401 `sign_in_required` |
| `lib/resolve-key.ts` | `validId(raw)`, `resolveKey(env, raw)` → `vulns.key` or null |
| `lib/search-params.ts` | `parseSearchParams(URLSearchParams)`, `SEARCH_TYPES`, `SEVERITIES`, `MAX_QUERY_CHARS = 200` |
| `migrations/users/0001_init.sql` | `users(id, email, name, created_at, plan, alert_frequency CHECK in instant/daily/weekly/off, alert_triggers, digest_weekday, email_suppressed, deleted_at)`, `watch(user_id, entry_key, created_at, alerts_on)`, `saved_searches(user_id, id, label, query, created_at)`, `alert_queue`, `alerts_sent`, `email_log`, `webhook_events`. Applied to staging |
| `packages/db/src/schema/users.ts` | Drizzle mirror of the SQL; `packages/db/test/schema.workers.test.ts` compares its columns to `PRAGMA table_info` |
| Tests | `apps/api/test/public-api.workers.test.ts` fakes sign-in: route modules mounted on a test `Hono` app with a middleware that sets `clerkAuth` from an `x-test-user` header (`vi.mock('@hono/clerk-auth')` does not work in this pool). `vitest.workers.mts` sets `CLERK_SECRET_KEY: 'sk_test_dummy'` and `CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_dGVzdC1zaWduaW5nLXNlY3JldA=='` |

Gaps in the schema: settings need instant alerts **and** a digest cadence at once, but `alert_frequency` holds
one value; there is no user-set display name separate from the Clerk name the webhook overwrites; saved
searches have no `params` or `alerts_on`. Section 1 adds one migration for these.

## What to build

Edit only: `apps/api/src/routes/{me,watch,saved-searches,webhooks-clerk}.ts`; `apps/api/src/lib/{delete-user,
clerk-api,account}.ts` (new or existing); new `packages/core/src/account.ts`; new
`packages/db/migrations/users/0002_account_settings.sql`; `packages/db/src/schema/users.ts` (mirror only); new
`apps/api/test/account.workers.test.ts` and `apps/api/test/webhooks-clerk.workers.test.ts`. Don't edit
`apps/api/src/index.ts`, `lib/env.ts`, `lib/auth.ts`, `lib/resolve-key.ts`, `lib/search-params.ts`,
`vitest.workers.mts`, Wrangler configs, `0001_init.sql`, other apps, or `pnpm-lock.yaml`. Add no dependency.

### 1. Migration `packages/db/migrations/users/0002_account_settings.sql`

```sql
ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN alert_instant INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN digest TEXT NOT NULL DEFAULT 'daily' CHECK (digest IN ('daily','weekly','off'));
UPDATE users SET alert_instant = 1, digest = 'off' WHERE alert_frequency = 'instant';
UPDATE users SET digest = alert_frequency WHERE alert_frequency IN ('weekly','off');
ALTER TABLE saved_searches ADD COLUMN params TEXT NOT NULL DEFAULT '{}';
ALTER TABLE saved_searches ADD COLUMN alerts_on INTEGER NOT NULL DEFAULT 0;
```

- `display_name` is what the user typed; `name` stays the Clerk name the webhook keeps in sync. Shown name =
  `display_name ?? name`.
- `alert_frequency` is superseded by `alert_instant` + `digest`. This change neither reads nor writes it; the
  alerts sender reads the new columns when it is built. Dropping it is left for later.
- Add the five columns to `packages/db/src/schema/users.ts` so the schema test passes.

### 2. Response types: `packages/core/src/account.ts`

Types and limits only. JSON is camelCase. Every type gets a one-line doc comment.

```ts
export const MAX_WATCH_ITEMS = 1000;
export const MAX_SAVED_SEARCHES = 50;
export const MAX_DISPLAY_NAME_CHARS = 80;
export const MAX_SAVED_SEARCH_NAME_CHARS = 80;

export type DigestCadence = 'daily' | 'weekly' | 'off';
export interface AlertSettings { instant: boolean; digest: DigestCadence; digestWeekday: number } // 0 = Sunday, UTC
export interface Me { userId: string; email: string; displayName: string | null; alerts: AlertSettings }
export interface MePatch { displayName?: string | null; alerts?: Partial<AlertSettings> }

export interface WatchItem { entryKey: string; title: string; alertsOn: boolean; createdAt: string }
export interface WatchListResponse { items: WatchItem[]; limit: number }

/** The filters of GET /v1/search, by its query-parameter names. */
export interface SavedSearchParams { type?: string[]; sig?: string[]; sev?: string[]; year?: string[]; sort?: 'rel' | 'new' }
export interface SavedSearch { id: string; name: string; query: string; params: SavedSearchParams; alertsOn: boolean; createdAt: string }
export interface SavedSearchCreate { name: string; query: string; params?: SavedSearchParams; alertsOn?: boolean }
export interface SavedSearchListResponse { items: SavedSearch[]; limit: number }

export interface DeleteAccountResponse { deleted: true }
```

### 3. Clerk Backend API: `apps/api/src/lib/clerk-api.ts`

```ts
export const CLERK_API_BASE = 'https://api.clerk.com/v1';
export class ClerkApiError extends Error { constructor(readonly status: number, message: string) }
export interface ClerkUserBasics { id: string; email: string; name: string | null }
export async function getClerkUser(secretKey: string, userId: string): Promise<ClerkUserBasics | null>;
export async function deleteClerkUser(secretKey: string, userId: string): Promise<void>;
```

- Plain `fetch` to `${CLERK_API_BASE}/users/${encodeURIComponent(userId)}` with
  `Authorization: Bearer <secretKey>` and `AbortSignal.timeout(10_000)`. Call `globalThis.fetch` at call time
  so tests can spy on it. No `@clerk/backend` client here: the tests must control every outbound request.
- `getClerkUser`: 404 → null; 2xx → parse with Zod (`id`, `email_addresses[{id, email_address}]`,
  `primary_email_address_id`, `first_name`, `last_name`, all nullable where Clerk allows); email = primary, else
  first, else `''`; name = first + last joined, or null.
- `deleteClerkUser`: 2xx or 404 → resolve (idempotent); anything else → `ClerkApiError`.
- An empty `secretKey` throws `ClerkApiError(503, 'clerk not configured')` before any fetch. Never log the key
  or the user's email; log the user ID and status only.

### 4. Account helpers: `apps/api/src/lib/account.ts`

- `toMe(row)`, `toWatchItem(row, title)`, `toSavedSearch(row)` map rows to the §2 types.
- `loadOrCreateUser(env, userId): Promise<UserRow>`: select the `users` row; if absent (the webhook has not
  arrived, or staging has no webhook secret yet), call `getClerkUser`, then
  `INSERT … ON CONFLICT(id) DO NOTHING` with `created_at` now and `digest_weekday` = today's UTC weekday, and
  select again. Clerk returns null → 401 `sign_in_required`; Clerk fails → 502 `clerk_unavailable`.
- `titlesFor(env, keys)`: `SELECT key, title FROM vulns WHERE key IN (…)` on `DB_VULNS` in chunks of 100 bound
  values via one `batch`; returns a `Map`. A key with no row maps to the key itself.
- `deleteUserData` in `lib/delete-user.ts` keeps its signature and one-batch shape; add a comment listing the
  tables it covers. Every `ti_users` table with a `user_id`/`id` for the user is covered; `email_log` and
  `webhook_events` hold no user data.

### 5. Routes

All `/v1/me*` responses set `cache-control: private, no-store`. Errors are `ApiError` (`{ error }`). Bodies are
parsed with Zod `.strict()`; a body that is not JSON, is over 4 KB, or fails the schema → 400 `bad_request`.

- `GET /v1/me` → `Me` via `loadOrCreateUser`.
- `PATCH /v1/me` with `MePatch` → updated `Me`. At least one field. `displayName`: trimmed, 1–80 chars, or
  `null` to clear; control characters rejected. `alerts.digest` in the union; `alerts.digestWeekday` integer
  0–6; `alerts.instant` boolean. One `UPDATE` for the given fields only.
- `DELETE /v1/me` → `deleteUserData(DB_USERS, userId)`, then `deleteClerkUser`. Success → 200
  `{ deleted: true }`. Clerk failure → 502 `clerk_delete_failed`; our rows are already gone and a retry is
  safe. Repeating the call after success returns 200 again (Clerk 404 counts as done). Does not call
  `loadOrCreateUser`.
- `GET /v1/me/watch` → `WatchListResponse`, newest first, all items (at most 1,000), with titles from
  `titlesFor`; `limit` = `MAX_WATCH_ITEMS`.
- `PUT /v1/me/watch/:id`, optional body `{ alertsOn?: boolean }` → `WatchItem`. `validId` fails → 400
  `bad_id`; `resolveKey` null → 404 `not_found`. The stored key is the resolved `vulns.key`, so a GHSA alias
  and its CVE are one item. Existing item: update `alerts_on` only if given. New item: `alerts_on` default 1,
  inserted with `INSERT … SELECT … WHERE (SELECT COUNT(*) FROM watch WHERE user_id = ?1) < 1000`; zero
  changes → 409 `limit_reached`. Same status (200) for create and update.
- `DELETE /v1/me/watch/:id` → `validId` fails → 400 `bad_id`; deletes `entry_key = validId(id)` and also the
  resolved key if it differs; always 200 `{ ok: true }` (idempotent).
- `GET /v1/me/saved-searches` → `SavedSearchListResponse`, newest first; `limit` = 50.
- `POST /v1/me/saved-searches` with `SavedSearchCreate` → 201 `SavedSearch`. `name` trimmed 1–80; `query`
  trimmed 0–200. Validate `query` + `params` by building `URLSearchParams` and running `parseSearchParams`;
  not ok → 400 `bad_request`. Store only the keys in `SavedSearchParams`, as JSON. `id` =
  `crypto.randomUUID()`; DB column `label` holds `name`. Cap with the same conditional insert at 50 → 409
  `limit_reached`.
- `DELETE /v1/me/saved-searches/:id` → id not a UUID → 400 `bad_id`; no such row **for this user** → 404
  `not_found`; else 200 `{ ok: true }`. Another user's id behaves exactly like a missing one.

### 6. Clerk webhook: `routes/webhooks-clerk.ts`

- Keep the existing behaviour for `user.created` and `user.updated` (they do not touch `display_name` or the
  alert columns).
- Fail closed: an empty or missing `CLERK_WEBHOOK_SIGNING_SECRET` → 400, nothing read or written (already true
  through `verifySvix`; add the test).
- Fix the dedupe order: if the `svix-id` is already in `webhook_events`, return 200; otherwise handle the
  event, **then** insert the id. Handlers are idempotent, so a concurrent duplicate is harmless; a handler
  error returns 500 and Clerk retries.
- `user.deleted` with `data.id` → `deleteUserData`. It does not call Clerk.

### 7. Tests

`apps/api/test/account.workers.test.ts`: mount `me`, `watch` and `saved-searches` on a test `Hono` app with
the `x-test-user` middleware from `public-api.workers.test.ts`. Fake Clerk with
`vi.spyOn(globalThis, 'fetch')`, answering only `https://api.clerk.com/v1/users/<id>` and failing the test on
any other URL; restore after each test. Cover:

1. Every route without the header → 401 `sign_in_required`.
2. `GET /v1/me` with no row → one Clerk `GET` with the bearer key, row created, `Me` with defaults; a second
   call makes no Clerk request. Clerk 500 → 502 `clerk_unavailable`.
3. `PATCH /v1/me`: name set, name cleared, each alert field, empty body, unknown key, weekday 7, 81-char name
   → expected status and stored values.
4. Watch: PUT by CVE, by an alias seeded in `advisories` (stored as the CVE), unknown id 404, bad id 400;
   GET returns titles and camelCase; alertsOn toggle; DELETE idempotent; the 1,001st item → 409 (seed 1,000
   rows directly) while updating an existing one still works.
5. Saved searches: create, list, invalid `params` (`type=bogus`, `sev=urgent`), 201-char query, 51st → 409,
   delete own, delete another user's id → 404 and the row survives.
6. `DELETE /v1/me`: seeds rows in all five tables for users A and B; deleting A removes all of A's rows,
   leaves B's, sends one Clerk `DELETE`; a repeat with Clerk 404 → 200; Clerk 500 → 502 with rows gone.

`apps/api/test/webhooks-clerk.workers.test.ts`: call the real `app` from `src/index`. Sign bodies the Svix way
(`v1,` + base64 HMAC-SHA256 of `<svix-id>.<svix-timestamp>.<body>` keyed with the base64 after `whsec_`) using
the test secret. Cover: `user.created` writes the row; replayed `svix-id` is a no-op; `user.deleted` clears all
of the user's rows and none of another's; a bad signature → 400; a correctly signed event with the secret set
to `''` → 400 and no `users` or `webhook_events` row; a handler failure (for example a stubbed `DB_USERS`
whose batch throws) → 500 and no `webhook_events` row, so the retry runs.

## Not in scope

Data export as JSON (`GET /v1/me/export`); alert triggers editing (`alert_triggers`); dropping
`alert_frequency`; sending any email; rate limiting; deleting deep-query jobs or other non-`ti_users` data;
soft delete via `deleted_at` (deletes are hard); the web account pages; `index.ts`, `env.ts`, `auth.ts`.

## Acceptance criteria

1. `pnpm build`, `pnpm typecheck` and `pnpm test:workers` pass, including the existing schema test with
   `0002_account_settings.sql` applied.
2. `@ti/core/account` exports the names in §2; the route handlers are typed against them.
3. Every route in §5 behaves as written; the tests in §7 exist and pass.
4. `DELETE /v1/me` and `user.deleted` leave no row for the user in `users`, `watch`, `saved_searches`,
   `alert_queue` or `alerts_sent`, and touch no other user's rows.
5. The webhook returns 400 and writes nothing when the signing secret is missing, and a failed handler does
   not record the `svix-id`.
6. No test makes a real network request; the only outbound host in code is `api.clerk.com`.
7. `git diff --stat main` shows only the files listed under What to build.
8. Proof saved: `pnpm build` and `pnpm test:workers` output; `wrangler dev` of the api on port 8700 with local
   D1 migrated, and `curl -i` for `GET /v1/me` (401), `PUT /v1/me/watch/CVE-2025-0001` (401), and an unsigned
   `POST /webhooks/clerk` (400). Signed-in behaviour is proven by tests only: the sandbox has no Clerk keys,
   and the PR says so.
