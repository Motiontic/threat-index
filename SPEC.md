# notify-engine: match changes to watchlists and saved searches, send instant alerts and digests

## Why

`ti-notify` consumes the collector's `run-finished` message every 3 hours and acks it untouched. Users can
already watch entries, save searches and choose instant alerts and a digest cadence (`/v1/me*`), but nothing
reads those settings. This change builds `docs/IMPLEMENTATION_PLAN.md` §10, steps 1–5: collect new `changes`
rows, match them to watch rows and saved searches, and send at most one email per user per run, under the
95-a-day cap, without duplicates on retry. With no Resend key (staging today) the worker logs what it would
send and records it as a dry run, so the whole flow is testable.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/notify/src/consume.ts` | `Env { DB_SIGNALS, DB_USERS, RESEND_API_KEY, UNSUBSCRIBE_SECRET, EMAIL_FROM, APP_BASE }`; `sendBatch` (Resend batch API, unused), `remainingToday`, `unsubscribeHeaders`; `consume` acks every message (`TODO(M3)`) |
| `apps/notify/src/index.ts` | `queue()` → `consume`; no HTTP or cron handler |
| `apps/notify/wrangler.jsonc` | `ti-notify` consumer (batch 1, 5 retries, no `max_concurrency`); `DB_SIGNALS`, `DB_USERS`; vars `EMAIL_FROM`, `APP_BASE` (production literal `https://<domain>`, staging `${TI_APP_URL_STAGING}`). No vitest project, no tests |
| Collector | sends `{ kind: 'run-finished', at: Date.now() }` to `NOTIFY` on the `0 */3 * * *` cron |
| `ti_signals.changes` | `id` (ULID), `entity_key`, `kind` (newly_exploited, public_exploit, epss_band, fix_released, cvss_change, breach_notice), `old`, `new`, `at` (indexed, ISO, set at link time), `source`. Vuln changes use the vuln key; `breach_notice` uses the company key and `new` = `<source>:<notice id>`. Rows from E2B jobs reach D1 later through the loader, so a row can land with an `at` older than rows already written |
| `ti_users` (0001 + 0002) | `users(…, alert_triggers JSON, digest_weekday 0–6 (0 = Sunday, UTC), email_suppressed, deleted_at, alert_instant 0/1, digest 'daily'/'weekly'/'off')`; `watch(user_id, entry_key, alerts_on)` indexed on `entry_key`; `saved_searches(user_id, id, label, query, params JSON, alerts_on)`; `alert_queue(user_id, change_id, created_at)`; `alerts_sent(user_id, change_id, sent_at)`; `email_log(day, sent)` |
| `apps/api/src/routes/unsubscribe.ts` | accepts `t=<payload>.<hex HMAC-SHA256 of payload>` keyed with `UNSUBSCRIBE_SECRET`; the payload format is not defined yet |
| `@ti/core` | `EMAIL_DAILY_CAP = 95`, `utcDay()` in `budget.ts`; `searchTerms()` in `search.ts`; `SavedSearchParams` in `account.ts`. `@ti/sources/registry` has `SOURCE_BY_ID` with a `credit` per source |

## What to build

Touch only `apps/notify/**`, new `packages/core/src/email.ts` (+ `email.test.ts`), new
`packages/db/migrations/users/0003_notify.sql`, the matching Drizzle mirror lines in
`packages/db/src/schema/users.ts` (append only, so the schema test passes), and the `apps/notify` importer in
`pnpm-lock.yaml` (adding the workspace dependency `@ti/sources`). Add no npm dependency.

### 1. Shared email contract: `packages/core/src/email.ts`

```ts
export const EMAIL_KINDS = ['instant', 'daily', 'weekly'] as const;
export type EmailKind = (typeof EMAIL_KINDS)[number];
export const UNSUBSCRIBE_PATH = '/unsubscribe';
export async function signUnsubscribeToken(secret: string, userId: string): Promise<string>;
export async function readUnsubscribeToken(secret: string | undefined, token: string | null | undefined): Promise<{ userId: string } | null>;
export function unsubscribeUrl(apiBase: string, token: string): string; // `${apiBase}/unsubscribe?t=<encoded token>`
export async function emailIdempotencyKey(userId: string, kind: EmailKind, changeIds: readonly string[]): Promise<string>;
```

- Token = `<payload>.<sig>`. `payload` = base64url (no padding) of `JSON.stringify({ v: 1, u: userId })`;
  `sig` = lowercase hex HMAC-SHA256 of the payload string, keyed with the secret's UTF-8 bytes. This is exactly
  what `verifyHmac` in the API checks, so the unsubscribe route can verify it and use `readUnsubscribeToken`
  to get the user. Tokens do not expire. Web Crypto only.
- `signUnsubscribeToken` throws on an empty secret or empty user ID. `readUnsubscribeToken` returns null on a
  missing secret, a missing or malformed token, a bad signature (constant-time compare), bad JSON, `v !== 1`,
  or `u` not a 1–128 char string. It never throws.
- `emailIdempotencyKey` = `ti-<kind>-` + the first 40 hex chars of SHA-256 of `userId\nkind\n<ids sorted,
  comma-joined>`. Same inputs in any order give the same key; no user ID appears in clear.
- `email.test.ts` (Node): round trip; tampered payload or signature → null; empty secret → sign throws, read
  null; the signature equals an HMAC computed independently in the test; idempotency key stability and that
  user, kind and ids each change it.

### 2. Migration `packages/db/migrations/users/0003_notify.sql`

```sql
ALTER TABLE alert_queue ADD COLUMN via TEXT NOT NULL DEFAULT 'watch'; -- 'watch' | 'search:<saved search id>'
CREATE TABLE notify_state (name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE email_sends (
  idem_key TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('instant','daily','weekly')),
  change_count INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','sent','dry_run','failed')),
  provider_id TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
) WITHOUT ROWID;
```

`email_sends` holds no user ID or address (the key is a hash), so account deletion needs no change. Add
`via`, `notify_state` and `email_sends` to `packages/db/src/schema/users.ts` and nothing else there.

### 3. Config: `apps/notify/wrangler.jsonc`, `package.json`, `src/env.ts`

- Add `DB_VULNS` (`ti_vulns` / `ti_vulns_staging`) and `DB_WORLD` (`ti_world` / `ti_world_staging`) for
  titles and saved-search fields. Add var `API_BASE` = `${TI_API_URL}` (production) and
  `${TI_API_URL_STAGING}` (staging); set production `APP_BASE` to `${TI_APP_URL}`. Add
  `"max_concurrency": 1` to both consumers so two runs never overlap.
- `Env` moves to `src/env.ts`: the four databases, `EMAIL_FROM`, `APP_BASE`, `API_BASE`,
  `UNSUBSCRIBE_SECRET: string`, `RESEND_API_KEY?: string`. A missing or empty `UNSUBSCRIBE_SECRET` makes the
  send step skip every email and log `notify.no_unsubscribe_secret` (never send mail without a working
  unsubscribe link); matching still runs.
- `package.json`: add `"@ti/sources": "workspace:*"`; scripts unchanged.

### 4. Limits (`src/limits.ts`, exported constants)

`MAX_CHANGES_PER_RUN = 500`, `LATE_WINDOW_HOURS = 6`, `FIRST_RUN_WINDOW_HOURS = 3`, `MAX_ITEMS_PER_EMAIL =
50`, `MAX_EMAILS_PER_RUN = 40` (stays under 50 subrequests a run), `SEND_GAP_MS = 600` (Resend's default rate
limit; check the current figure in Resend's docs and cite it in the PR), `DIGEST_HOUR_UTC = 3`,
`QUEUE_TTL_DAYS = 14`, `SENT_TTL_DAYS = 30`, `D1_CHUNK = 90` bound values per `IN (…)`.

### 5. The run: `src/consume.ts` → `runNotify(env, runAt, deps)`

`consume` checks each body by hand (`kind === 'run-finished'`, `at` a finite number within a year of now);
anything else is acked and logged `notify.bad_message`. Otherwise it calls `runNotify(env, new Date(at))`
and acks; a throw → `msg.retry({ delaySeconds: 300 })`. `deps = { fetch, sleep, now }` default to the
globals (`globalThis.fetch` read at call time) so tests can replace them. `runAt` (the cron time) decides
digests, not the wall clock. Steps, in order:

1. **Collect** (`src/collect.ts`). Cursor = `notify_state` row `cursor`, value JSON `{ at, id }`. With no row,
   start at `runAt − 3 h` (never mail the history). Forward read: `changes WHERE (at, id) > (?, ?) ORDER BY at,
   id LIMIT 500`. Late read: `changes WHERE at > cursor.at − 6 h AND at <= cursor.at ORDER BY at, id LIMIT
   500`, for rows the loader wrote after the cursor passed them. Both sets go to matching; duplicates are
   harmless (step 2 dedupes). When the forward read is full, log `notify.backlog`; the rest waits a run.
2. **Match** (`src/match.ts`). Users count only when `email_suppressed = 0`, `deleted_at IS NULL`, `email`
   not empty, and the change kind is in their `alert_triggers` (invalid JSON → all five defaults).
   - Watch: `watch JOIN users WHERE alerts_on = 1 AND entry_key IN (…)` in chunks. Queue with `via =
     'watch'` when `alert_instant = 1` or `digest != 'off'`.
   - Saved searches: load `saved_searches JOIN users WHERE alerts_on = 1 AND digest != 'off'` (at most 5,000
     rows; log if more). Fetch the changed entities: `vulns(key, title, summary, cvss, kev_added, published)`
     from `DB_VULNS`, `companies(key, name)` from `DB_WORLD`. Pure `matchesSearch(search, doc)`: every term
     of `searchTerms(query).slice(0, 8)` is in `searchTerms(key + title + summary)` (company: key + name);
     `type` filter: a vuln is `vuln`, a breach notice is `breach`; `sig=kev` needs `kev_added`; `sev` uses the
     search route's CVSS bands (critical ≥ 9, high 7–9, medium 4–7, low > 0); `year` = first 4 chars of
     `published`. An empty query with no filters matches nothing. Queue with `via = 'search:<id>'`.
   - Write `INSERT OR IGNORE INTO alert_queue (user_id, change_id, created_at, via) SELECT … WHERE NOT EXISTS
     (SELECT 1 FROM alerts_sent WHERE user_id = ? AND change_id = ?)` in one `batch`, watch rows first so a
     change matched both ways is kept as `watch`. Then save the cursor (last forward row) in the same batch.
3. **Plan** (`src/plan.ts`, pure). Load `alert_queue JOIN users` (≤ 5,000 rows), the changes they name
   (rows whose change is gone are deleted), titles as above. Per user (skip and delete the rows of suppressed,
   deleted or email-less users):
   - `instant` items: `via = 'watch'` rows when `alert_instant = 1`.
   - A digest is due when `runAt` hour is 3 and `digest = 'daily'`, or `digest = 'weekly'` and
     `runAt.getUTCDay() = digest_weekday`. Its items are all the user's rows.
   - Digest due → one email of kind `daily`/`weekly` (watched entries first, then saved-search matches).
     Else instant items → one `instant` email. Else nothing. So a user never gets two emails in one run.
   - Items newest change first, at most 50 per email; the rest stay queued. Priority: any instant items → 0,
     else `daily` 1, `weekly` 2; ties by oldest queued row, then user ID. Keep the first 40.
4. **Render** (`src/render.ts`, pure) → `{ subject, text, html }`. See section 6.
5. **Send** (`src/send.ts`), one email at a time, `SEND_GAP_MS` apart:
   - Key = `emailIdempotencyKey(user, kind, change ids)`. `INSERT … ON CONFLICT DO NOTHING` an `email_sends`
     row (`pending`). If it is already `sent` or `dry_run`, skip the send and only finish the bookkeeping.
   - Reserve a cap slot: `email_log` upsert for `utcDay(runAt)`, then `UPDATE … SET sent = sent + 1 WHERE day
     = ? AND sent < 95`; zero changes → stop sending this run (everything left stays queued).
   - `RESEND_API_KEY` set: `POST https://api.resend.com/emails` with `Authorization: Bearer`,
     `Idempotency-Key: <key>`, `AbortSignal.timeout(10_000)`, body `{ from: EMAIL_FROM, to: [email], subject,
     text, html, headers }` where headers are `List-Unsubscribe: <https URL>` and `List-Unsubscribe-Post:
     List-Unsubscribe=One-Click`. 2xx → `sent` with the returned `id`. Other 4xx → `failed`, release the slot,
     continue. 429, 5xx, timeout or network error → `failed`, release the slot, stop sending this run.
   - No key: log one JSON line `{ event: 'notify.dry_run', kind, items, key }` and mark `dry_run`. It counts
     against the cap like a real send.
   - Bookkeeping after `sent`/`dry_run`, in one batch: status update, `INSERT OR IGNORE INTO alerts_sent` per
     change, delete those `alert_queue` rows. Failed sends leave the queue rows for the next run.
6. **Prune** on the 03:00 run: `alert_queue` rows older than 14 days, `alerts_sent` and `email_sends` older
   than 30 days, `email_log` days older than 30 days.

Logs carry user IDs, counts and keys only: never an address, subject or body. One summary line per run:
`notify.run` with changes read, rows queued, emails by kind and status, cap left.

### 6. Templates (`src/render.ts`)

- Subjects: instant with one item `Threat Index: <title> <short change>`, otherwise `Threat Index: <n>
  updates on your watchlist`; `Threat Index daily digest: <n> updates` and `Threat Index weekly digest: <n>
  updates`. One line, ≤ 150 chars, control characters stripped.
- One line per item: title (vuln title or key, company name or key, ≤ 140 chars), the change in words
  (`Exploited in the wild: added to CISA KEV on <new>`, `Public exploit published`, `EPSS moved from <old> to
  <new>` as percentages, `Fix released`, `CVSS changed from <old> to <new>`, `New breach notice`), and a link:
  `${APP_BASE}/e/<encoded key>` for vulns, `${APP_BASE}/search?type=breach&q=<encoded name>` for companies.
  Saved-search items are grouped under `Matches for "<label>"`.
- Footer: why the email was sent, `Manage alerts: ${APP_BASE}/account`, a visible unsubscribe link (same URL
  as the header), a credits line `Data: <credits>` built from `SOURCE_BY_ID.get(change.source)?.credit`
  (deduped; `Source: <id>` when unknown), and `Threat Index by Motiontic`.
- HTML: one 600 px table, inline styles only, the site's tokens (background `#fafaf8`, card `#ffffff`, ink
  `#121212`, muted `#6b6a64`, rules `#e6e4de`, accent `#ef7d45` for the change label), system sans-serif.
  No images, remote fonts, scripts or tracking. Every value from the database is HTML-escaped and every URL
  built with `encodeURIComponent`. The text part says the same as the HTML part.

### 7. Tests

`apps/notify/vitest.workers.mts` with `workerProject(…, 'notify', 'notify', ['test/**/*.workers.test.ts'],
{ DB_SIGNALS, DB_USERS, DB_VULNS, DB_WORLD }, { UNSUBSCRIBE_SECRET: 'test-unsubscribe-secret' })`, and
`test/env.d.ts` typing `cloudflare:workers` `env` as `Env`. Tests call `runNotify`/`consume` with a fake
`fetch` that answers only `https://api.resend.com/emails` (any other URL fails the test) and a no-op `sleep`;
`RESEND_API_KEY` is set per test by passing `{ ...env, RESEND_API_KEY: 're_test' }`. Node tests in
`apps/notify/test/*.test.ts` cover `matchesSearch`, `plan` and `render` (escaping, subjects, links, credits).

Workers tests (`test/notify.workers.test.ts`), each with seeded rows:
1. Instant user, two watched entries, three changes → one request: bearer, `Idempotency-Key`, one recipient,
   both unsubscribe headers (the token reads back to the user with `readUnsubscribeToken`), text and HTML with
   entry links and credits; then `alerts_sent` rows, empty queue, `sent`, `email_log.sent = 1`.
2. The same message again → no request. A crash replay (pre-seeded `pending` row and queue rows) → one
   request with the same `Idempotency-Key`.
3. Daily user: a 09:00 run queues and sends nothing; the 03:00 run sends one `daily`. Weekly user: 03:00 on
   another weekday → nothing; on `digest_weekday` → one `weekly`.
4. Instant + daily user at 03:00 with a watch and a search match → exactly one email holding both.
5. Saved searches: a matching query + `sev=critical` queues; a non-matching one, `alerts_on = 0`, and
   `digest = 'off'` do not. A user without `cvss_change` in `alert_triggers` gets nothing for that kind.
6. Suppressed and deleted users get no request and their queue rows are removed.
7. Cap: `email_log` seeded at 93 → the instant email and one daily go, two daily users stay queued,
   `sent = 95`; a run on the next day sends them.
8. Dry run (no key): no request, `dry_run` rows, queue cleared, counts toward the cap, and no logged line
   contains `@`.
9. Resend 422 → `failed`, slot released, rows kept, next email still sent; 500 → sending stops, no throw.
10. Cursor: a first run ignores changes older than 3 h; a row written later with an `at` before the cursor
    (within 6 h) is matched on the next run; a sent change is never queued again.
11. A bad message body is acked and writes nothing; a D1 failure during matching retries the message.

## Not in scope

Unsubscribe and Resend webhook handling (the API routes); the alert settings UI; Resend domain setup and the
production `EMAIL_FROM`; a `mailto:` unsubscribe (RFC 8058 needs only the HTTPS one); the watchdog's 80% cap
warning and `budget.emails_sent`; metering notify's D1 writes; watching companies; per-user time zones;
continuing a backlog within the same run; the 7-day soak test.

## Acceptance criteria

1. `pnpm build` passes; `pnpm test:workers` passes with the tests in section 7, including the existing
   `ti_users` schema test with `0003_notify.sql` applied; `pnpm test` runs the Node tests.
2. `@ti/core/email` exports the names in section 1, and a token it signs passes the API's current
   `tokenOk` check (prove with a test that imports nothing from `apps/api` but recomputes the same HMAC).
3. `rg -n "TODO|sendBatch|<domain>" apps/notify/src` finds nothing; the only outbound host in
   `apps/notify/src` is `api.resend.com`.
4. No test makes a real network request; no log line in any test contains an email address.
5. `git diff --name-only main` lists only the files named under What to build.
6. Proof saved: `pnpm build` and `pnpm test:workers` output; the rendered instant and daily sample emails
   (text and HTML, dummy data) written by a test to the proof folder, with a browser screenshot of the HTML;
   and `wrangler dev` of notify on port 8700 with local D1 migrated, showing it starts with the new bindings.
   Real sending is untested here (no Resend key in the sandbox); the PR says so.

## Coordination with work merged just before this

- One-click unsubscribe merged first and owns the token format: import `signUnsubscribeToken`,
  `unsubscribeUrl` and `UnsubscribeScope` from `@ti/core/unsubscribe` (on main). Do not define a token format in
  `@ti/core/email`. Instant emails use scope `watch` with the item id when the mail is about one watched entry,
  else `all`; digests use scope `digest`. The List-Unsubscribe header and the footer link both use these tokens.
- The account is on Workers Paid (1,000 subrequests per invocation), but keep the 40-sends-per-run limit
  anyway; it spaces mail out.

## Changes from the first build of this branch

The coordination section wins over section 1 and acceptance criterion 2. `@ti/core/email` defines no token
format and exports no `signUnsubscribeToken`, `readUnsubscribeToken` or `unsubscribeUrl`. Use
`signUnsubscribeToken(secret, { userId, scope, item, issuedAt })` and `UNSUBSCRIBE_PATH` from
`@ti/core/unsubscribe` on main, with scope `watch` (with the item) for one-entry instant mail, else `all`, and
`digest` for digests. Build the URL as `<API_BASE><UNSUBSCRIBE_PATH>?t=<token>`. Add a test that a token from
the notify worker passes `verifyUnsubscribeToken`. Re-run every acceptance check.
