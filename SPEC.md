# email-lifecycle: one-click unsubscribe and Resend bounce and complaint suppression

## Why

Alert email is only allowed if people can leave it in one click and if addresses that bounce or complain stop
getting mail. `docs/IMPLEMENTATION_PLAN.md` §8 lists `GET/POST /unsubscribe` (signed token, RFC 8058 one-click)
and `POST /webhooks/resend` (bounce or complaint → `email_suppressed = 1`), and §10 requires both before any
alert is sent. On main both routes check their auth and then return 501.

The notify worker is built at the same time on its own branch. It signs unsubscribe links and must use the
exact token format this route accepts, so this change also adds the shared signing helper in `@ti/core`.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/routes/unsubscribe.ts` | `GET` and `POST /unsubscribe`: token from query `t`, format `<payload>.<hmac hex>`, checked with `verifyHmac(UNSUBSCRIBE_SECRET, payload, hmac)`; bad token → 401 `{"error":"invalid_token"}`; good token → 501. The payload format is undefined |
| `apps/api/src/routes/webhooks-resend.ts` | `verifySvix(c, RESEND_WEBHOOK_SECRET)`; failure → 400 `Verification failed`; otherwise 501. No dedupe |
| `apps/api/src/routes/webhooks-clerk.ts` | Reference for Svix handling and `webhook_events` dedupe (the account work moves the insert to after handling) |
| `apps/api/src/lib/auth.ts` | `verifySvix` throws without a secret; `hmacHex`, `verifyHmac` (constant time, fails closed) |
| `apps/api/src/index.ts` | Mounts both routes outside `clerkMiddleware()`. Not edited here |
| `ti_users` (`0001_init.sql`) | `users.email`, `users.email_suppressed INTEGER NOT NULL DEFAULT 0`; `watch(user_id, entry_key, alerts_on)`; `saved_searches(user_id, id, …)`; `webhook_events(id, source, received_at)` |
| `0002_account_settings.sql` (account work, merged before this) | `users.alert_instant` (0/1), `users.digest` ('daily'\|'weekly'\|'off'), `saved_searches.alerts_on` (0/1) |
| `apps/api/test/api.workers.test.ts` | Expects `/unsubscribe?t=nope` → 401 and an unsigned `POST /webhooks/resend` → 400. Both must still pass |
| `apps/api/vitest.workers.mts` | Test secrets: `UNSUBSCRIBE_SECRET = 'test-unsubscribe-secret'`, `RESEND_WEBHOOK_SECRET = 'whsec_dGVzdC1yZXNlbmQtc2VjcmV0'` |

If `packages/db/migrations/users/0002_account_settings.sql` is not on main when the build starts, stop and
report it: the digest and saved-search scopes need its columns, and this branch may not add a migration.

## What to build

Touch only `packages/core/src/unsubscribe.ts` (+ `unsubscribe.test.ts`), `apps/api/src/routes/unsubscribe.ts`,
`apps/api/src/routes/webhooks-resend.ts`, new `apps/api/src/lib/unsubscribe.ts` and `apps/api/src/lib/suppress.ts`,
and new tests `apps/api/test/unsubscribe.workers.test.ts` and `apps/api/test/webhooks-resend.workers.test.ts`.
Don't edit `apps/api/src/index.ts`, `lib/env.ts`, `lib/auth.ts`, migrations, Wrangler configs, other apps,
`vitest.workers.mts` or `pnpm-lock.yaml`. Add no dependency.

### 1. Token format: `packages/core/src/unsubscribe.ts`

Web Crypto only, so it runs in Workers and Node 22. It has its own small HMAC helper; don't edit `sign.ts`.

```ts
export const UNSUBSCRIBE_PATH = '/unsubscribe';
export const MAX_UNSUBSCRIBE_TOKEN_CHARS = 1024;
export type UnsubscribeScope = 'all' | 'digest' | 'watch' | 'search';
/** `item` is the entry key for 'watch' and the saved-search id for 'search'; absent otherwise. */
export interface UnsubscribePayload { userId: string; scope: UnsubscribeScope; item?: string; issuedAt: number }
export async function signUnsubscribeToken(secret: string, payload: UnsubscribePayload): Promise<string>;
export async function verifyUnsubscribeToken(secret: string | undefined, token: string | undefined | null): Promise<UnsubscribePayload | null>;
/** `${apiBase without trailing slash}/unsubscribe?t=${token}` — the URL for the link and List-Unsubscribe. */
export function unsubscribeUrl(apiBase: string, token: string): string;
```

- Token = `<payload>.<hmac>`. `<payload>` is base64url without padding of the UTF-8 JSON
  `{"v":1,"u":<userId>,"s":<scope>,"i":<item>?,"t":<issuedAt>}` (keys in that order, `i` omitted when absent).
  `<hmac>` is lowercase hex HMAC-SHA256 of the `<payload>` string keyed with the secret. This keeps the format
  the stub's comment already states. Tokens contain only `[A-Za-z0-9_.-]`, so they need no URL encoding.
- `issuedAt` is whole Unix seconds. Tokens never expire; the issue date is kept for audits and a future
  rotation, and nothing reads it yet.
- `signUnsubscribeToken` throws on an empty secret, an empty `userId`, a `userId` or `item` over 256
  characters, an unknown scope, a missing `item` for `watch`/`search`, an `item` for `all`/`digest`, or a
  non-integer or negative `issuedAt`.
- `verifyUnsubscribeToken` returns `null`, never throws, for: no secret, no token, a token over
  `MAX_UNSUBSCRIBE_TOKEN_CHARS`, no `.`, a bad HMAC (constant-time compare), bad base64url, bad JSON, `v` not
  1, or any field that `signUnsubscribeToken` would reject. It splits on the last `.`. It checks the HMAC
  before decoding the payload.
- `unsubscribe.test.ts` (Node): round trip for each scope; a token signed with another secret, a flipped
  payload byte, a flipped HMAC character, a truncated token, an over-long token, `v: 2`, an `item` on `all`
  and an empty secret all verify to `null`; `sign` throws on each bad input above; one fixed vector
  (secret `test-unsubscribe-secret`, payload `{userId:'user_1', scope:'all', issuedAt:1700000000}`) whose exact
  token string is written in the test, so the notify worker can copy it.

### 2. Applying an unsubscribe: `apps/api/src/lib/unsubscribe.ts`

`applyUnsubscribe(db: D1Database, p: UnsubscribePayload): Promise<void>` runs one statement, always scoped
to `p.userId`:

| Scope | SQL |
| ----- | --- |
| `all` | `UPDATE users SET alert_instant = 0, digest = 'off' WHERE id = ?1` |
| `digest` | `UPDATE users SET digest = 'off' WHERE id = ?1` |
| `watch` | `UPDATE watch SET alerts_on = 0 WHERE user_id = ?1 AND entry_key = ?2` |
| `search` | `UPDATE saved_searches SET alerts_on = 0 WHERE user_id = ?1 AND id = ?2` |

- Idempotent: a second apply changes nothing and still succeeds. A user or item that no longer exists is not
  an error (0 rows changed → the same success page).
- Unsubscribing never sets `email_suppressed`: that flag is for bounces and complaints and is not
  user-reversible. Turning alerts back on later is done in account settings.
- The same file exports `renderPage(kind: 'confirm' | 'done' | 'invalid', p?: UnsubscribePayload, token?: string): string`:
  a small self-contained HTML page (inline CSS only, no scripts, no external resources, `lang="en"`,
  viewport meta). Text by scope: all → "all Threat Index alert email"; digest → "digest email";
  watch → "alerts for <entry key>"; search → "alerts for this saved search". `confirm` has one
  `<form method="post" action="/unsubscribe?t=<token>">` with a hidden `List-Unsubscribe=One-Click` field and
  one submit button. Every interpolated value is HTML-escaped (`& < > " '`).

### 3. Route: `apps/api/src/routes/unsubscribe.ts`

- `GET /unsubscribe?t=…`: verify with `verifyUnsubscribeToken(c.env.UNSUBSCRIBE_SECRET, t)`. Valid → 200
  `confirm` page, nothing written (mail scanners prefetch GET links). Invalid → 401 `invalid` page.
- `POST /unsubscribe?t=…`: the RFC 8058 one-click and the page's button. Token from the query only; the body
  is not required or parsed beyond what Hono reads. Valid → `applyUnsubscribe`, then 200 `done` page.
  Invalid → 401 `{"error":"invalid_token"}`. A D1 error → 500 `{"error":"internal"}` (the mail client
  retries).
- Every response: `Cache-Control: no-store`, `Referrer-Policy: no-referrer` (the token is in the URL),
  `X-Content-Type-Options: nosniff`, and on HTML `Content-Security-Policy: default-src 'none';
  style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`.
- No cookies or session are read; the token is the only auth. Log `{ route: 'unsubscribe', scope, applied }`
  only: never the token, user id or email.
- Missing or empty `UNSUBSCRIBE_SECRET` → every token is invalid (fail closed).

### 4. Suppression: `apps/api/src/lib/suppress.ts` and `routes/webhooks-resend.ts`

`suppressAddresses(db: D1Database, emails: string[]): Promise<number>` lowercases and trims each address,
drops empty ones and duplicates, caps the list at 50, and runs
`UPDATE users SET email_suppressed = 1 WHERE lower(email) = ?1 AND email_suppressed = 0` for each in one
`db.batch`. Returns the number of rows changed.

`POST /webhooks/resend`:

1. `verifySvix(c, c.env.RESEND_WEBHOOK_SECRET)`; any failure, including a missing or empty secret → 400
   `Verification failed`, nothing read or written.
2. `svix-id` already in `webhook_events` → 200 `OK`, nothing else.
3. Handle by `type`:
   - `email.bounced` with `data.bounce.type === 'Permanent'`, or with no `data.bounce` object → suppress every
     address in `data.to` (an array of strings; a single string is accepted too).
   - `email.bounced` with any other bounce type (`Transient`, `Undetermined`) → no change.
   - `email.complained` → suppress every address in `data.to`.
   - Any other type → no change.
   - A body that doesn't match (missing `data`, `to` not a string or string array) → no change, still 200, so
     Resend doesn't retry a payload we can never use.
4. Insert `(svix-id, 'resend', now)` into `webhook_events` **after** handling. A handler error → 500 and no
   `webhook_events` row, so Resend retries; the update is idempotent, so a retry is safe.
5. Log `{ route: 'webhooks-resend', type, suppressed: n }`; never an address.

Before writing the handler, check the current payload shape at https://resend.com/docs/dashboard/webhooks/event-types
with curl. If the field names differ from the above (`type`, `data.to`, `data.bounce.type`), follow the docs,
write the fixture to match, and say so in the PR. Save the real-shaped sample bodies (addresses replaced with
`@example.com`) under `fixtures/resend/` (`bounced-permanent.json`, `bounced-transient.json`,
`complained.json`, `delivered.json`) and load them with `fixture('resend', …)`.

### 5. Tests

`apps/api/test/unsubscribe.workers.test.ts`, calling the real `app` from `src/index` against local D1 with
user rows seeded (alert_instant 1, digest 'weekly', two watch rows, two saved searches with `alerts_on = 1`),
tokens made with `signUnsubscribeToken` and the test secret:

1. GET with a valid token → 200 HTML containing the form, the headers from §3, and no row changed.
2. POST `all` → `alert_instant = 0`, `digest = 'off'`; watch and saved-search rows untouched.
3. POST `digest` → only `digest = 'off'`.
4. POST `watch` → only that entry's `alerts_on = 0`; the other watch row and another user's row unchanged.
5. POST `search` → only that saved search's `alerts_on = 0`.
6. Applying twice → 200 both times, same end state. A token for a deleted user or item → 200, nothing written.
7. Bad token (wrong secret, tampered payload, `nope`) → GET 401 HTML, POST 401 JSON, nothing written.
8. `UNSUBSCRIBE_SECRET = ''` with an otherwise valid token → 401.
9. A token whose `item` is `<script>` renders escaped on the GET page.
10. POST with body `List-Unsubscribe=One-Click` and `Content-Type: application/x-www-form-urlencoded` (what
    mail clients send) and POST with no body both apply.

`apps/api/test/webhooks-resend.workers.test.ts`, signing bodies the Svix way (`v1,` + base64 HMAC-SHA256 of
`<svix-id>.<svix-timestamp>.<body>` keyed with the base64-decoded part after `whsec_`; current timestamp):

1. Permanent bounce → the matching user (stored with mixed-case email) gets `email_suppressed = 1`; another
   user does not; a `webhook_events` row with source `resend` exists.
2. Transient bounce → no change, 200, event recorded. Complaint → suppressed. `email.delivered` → no change.
3. Replayed `svix-id` after the user's flag is reset by the test → stays 0 (the replay did nothing).
4. Bad signature → 400; secret set to `''` with a correctly signed body → 400; neither writes any row.
5. An address with no user → 200, nothing changed. A malformed `data` → 200, nothing changed.
6. A handler failure (a stubbed `DB_USERS` whose `batch` throws) → 500 and no `webhook_events` row.

Tests make no network request.

## Not in scope

Sending email, `List-Unsubscribe` headers and links in messages (the notify worker, which uses
`signUnsubscribeToken` and `unsubscribeUrl`); `mailto:` unsubscribe handling; a preference centre or
re-subscribe page; un-suppressing an address; counting soft bounces; token rotation or revocation; rate
limiting; `index.ts`, `env.ts`, `auth.ts` and migrations.

## Acceptance criteria

1. `pnpm build`, `pnpm typecheck`, `pnpm test` and `pnpm test:workers` pass, including the two existing
   checks in `api.workers.test.ts`.
2. `@ti/core/unsubscribe` exports exactly the names and signatures in §1, and its fixed test vector is in
   `unsubscribe.test.ts`.
3. GET never writes; POST applies each scope exactly as the table in §2, only for the token's user, and is
   idempotent. The tests in §5 exist and pass.
4. The webhook returns 400 and writes nothing without a valid signature or with no secret; it dedupes by
   `svix-id`; a failed handler records no `svix-id`.
5. `rg -n "console\.(log|warn|error)" apps/api/src/routes/{unsubscribe,webhooks-resend}.ts apps/api/src/lib/{unsubscribe,suppress}.ts`
   shows no address, token or user id in any log call.
6. `git diff --stat main` shows only the files listed under What to build plus `fixtures/resend/*`.
7. Proof saved: `pnpm build` and `pnpm test:workers` output; whether the Resend docs were fetched and any
   payload difference found; `wrangler dev` of the api on port 8700 with local D1 migrated and a
   `.dev.vars` (not committed) holding a dummy `UNSUBSCRIBE_SECRET`, a user row inserted with
   `wrangler d1 execute --local`, and `curl -i` for: GET with a token signed by a one-line Node script (200),
   POST with the same token (200) followed by the `users` row showing `digest = 'off'`, GET `?t=nope` (401),
   and an unsigned `POST /webhooks/resend` (400). A signed Resend delivery is proven by tests only.
