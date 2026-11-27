# mcp-watch: package watches, alerts for new advisories, and watch tools in the MCP server

## Why

"Tell me if anything new hits langchain." Today a user can watch single entries (a CVE, an advisory), but not a
package, and an agent can't manage a watchlist at all. This change adds:

- package watches in the API (up to 200 per user);
- a `new_advisory` change when an advisory that names packages first appears, and alerts for package watches
  on that and on the existing change kinds;
- three MCP tools: `mti_watch_add`, `mti_watch_remove`, `mti_watch_list`;
- a yes/no question (elicitation) when a user adds a watch while their email alerts are off;
- an email to the user whenever their watchlist changes through MCP, so a stolen token can't quietly silence
  alerts.

## Current state (on main)

| Area | Today |
| ---- | ----- |
| `packages/db/migrations/users/0004_mcp.sql` | `watch_packages (user_id, ecosystem, name, created_at, alerts_on)`, primary key `(user_id, ecosystem, name)`, index `watch_packages_by_package (ecosystem, name)`. `package_usage`, `mcp_blocks` |
| `packages/db/migrations/users/0001–0003` | `users` has `email`, `alert_triggers` (JSON list, default `newly_exploited, public_exploit, epss_band, fix_released, breach_notice`), `alert_instant`, `digest` (`daily`/`weekly`/`off`), `digest_weekday`. `watch (user_id, entry_key, alerts_on, ...)`. `alert_queue (..., via)` with `via` `'watch'` or `'search:<id>'`. `alerts_sent`, `email_sends`, `notify_state` |
| `packages/db/migrations/advisories/0002_package_data.sql` | `package_advisories (source, source_id, vuln_key, status, summary, severity, reviewed, url, published, modified)` and `affected (ecosystem, name, source, source_id, range_no, vuln_key, range_type, introduced, fixed, last_affected, versions)`, indexes `affected_by_record (source, source_id)` and `affected_by_vuln (vuln_key)` |
| `packages/db/migrations/signals/0003` | `changes.kind` CHECK allows `new_advisory`. Nothing writes it yet |
| `packages/linker/src/affected.ts` | `packageWrites(record, plan, stored)` upserts `affected` and `package_advisories` rows for every advisory record (hot or cold). `stored.advisory` is the existing `package_advisories` row, if any |
| `packages/linker/src/changes.ts`, `detect.ts` | Change rows for vulns and breach notices; `detect.ts` already lists the `new_advisory` kind |
| `apps/api/src/routes/watch-packages.ts` | `GET /v1/me/watch/packages`, `PUT` and `DELETE /v1/me/watch/packages/:ecosystem/:name`: stubs (501) |
| `apps/api/src/routes/watch.ts` | Entry watches: `GET /v1/me/watch`, `PUT`/`DELETE /v1/me/watch/:id`; cap `MAX_WATCH_ITEMS` (1,000) with an atomic insert, 409 `limit_reached` |
| `apps/api/src/routes/me.ts` | `PATCH /v1/me` sets `displayName` and `alerts.{instant,digest,digestWeekday}` |
| `apps/api/src/lib/mcp-routes.ts` | Allow-list: the three package-watch routes and the entry-watch routes are listed (GETs `mti:read`, PUT/DELETE `mti:watch`). No `PATCH` entry; `McpRoute.method` has no `PATCH` |
| `apps/api/src/lib/mcp-identity.ts` | Sets `c.get('mcp')` (sub, scopes, clientId) for a signed MCP call |
| `apps/notify/src/*` | Runs on each `run-finished` queue message. `collect` reads new `changes`; `match.ts` queues entry-watch and saved-search matches; `plan.ts` sends instant alerts only for `via = 'watch'` and puts everything in digests; `render.ts` builds text and escaped HTML. The single-item instant subject includes the item's title. `DB_ADVISORIES` is bound but unused |
| `apps/mcp/src/tools/mti_watch_*.ts` | Stubs (`enabled: false`) |
| `apps/mcp/src/tools/shared.ts` | `registerTool` gives every tool the read-only hints and `requireScopes('mti:read')`. `apiJson` supports only GET and POST |
| SDK | `inputRequired` and `inputRequired.elicit(...)` build an `input_required` result; `requestState` is opaque and echoed back by the client; `ctx.mcpReq.requestState()` / `inputResponses` read it on the retry |

## What to build

### 1. Migration: `packages/db/migrations/users/0005_watch_events.sql`

```sql
CREATE TABLE watch_events (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, at TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('add','remove','alerts_on','digest_on')),
  target TEXT NOT NULL,                 -- 'pkg:<ecosystem>/<name>' or 'entry:<key>' or 'settings'
  via TEXT NOT NULL CHECK (via IN ('mcp')),
  client_host TEXT,                     -- host of the OAuth client_id URL, or NULL
  notified_at TEXT                      -- set when the change notice email went out
);
CREATE INDEX watch_events_by_user ON watch_events (user_id, at);
CREATE INDEX watch_events_pending ON watch_events (notified_at, user_id);
```

Only changes made through MCP are recorded (the website is the user acting directly). Rows older than 30 days
are deleted by notify.

### 2. API: package watches (`apps/api/src/routes/watch-packages.ts`)

- `GET /v1/me/watch/packages` → `{ items: [{ ecosystem, name, createdAt, alertsOn }], limit: 200 }`, newest
  first. (The tool merges this with entry watches into one list; section 6.)
- `PUT /v1/me/watch/packages/:ecosystem/:name`, body `{ alertsOn?: boolean }` (empty body allowed) →
  `{ created: boolean }`. Idempotent: an existing watch is kept (its `alertsOn` updated if given). An MCP
  caller may not send `alertsOn: false` (403 `not_allowed_for_mcp`).
- `DELETE /v1/me/watch/packages/:ecosystem/:name` → `{ removed: boolean }`.
- Path parameters come from `c.req.param()`, which already decodes once; don't decode again. `ecosystem` must be a canonical ecosystem (`canonicalEcosystem`),
  `name` is normalised with `normaliseName` and at most 214 characters. Anything else → 400
  `invalid_argument`. Scoped npm names (`@scope/pkg`) and Maven `group:artifact` arrive encoded in one segment.
- Cap: 200 package watches per user, enforced in the same statement as the insert (as `watch.ts` does). Over
  the cap → 409 `limit_reached`.
- For an MCP caller (`c.get('mcp')` set), every add, remove and alerts change writes a `watch_events` row in the
  same batch as the change. The entry-watch routes in `watch.ts` do the same for MCP callers.
- Removal cap for MCP callers: at most 20 removals (entry and package together) per user in any 24 hours,
  counted from `watch_events`. Over it → 429 `removal_limit` with `Retry-After`. The website is not capped.

### 3. API: turning alerts on from MCP (`apps/api/src/routes/me.ts`, `mcp-routes.ts`)

- `McpRoute.method` gains `PATCH`; add `watch('PATCH', '/v1/me')`.
- In `PATCH /v1/me`, an MCP caller may send only `{ "alerts": { "digest": "daily" | "weekly" } }`, and only
  while the stored digest is `off` (it can turn alerts on, never change or reduce them). Any other field, value
  or state from an MCP caller → 403 `not_allowed_for_mcp`. The website keeps its full body.
- An MCP digest change writes a `watch_events` row (`digest_on`, target `settings`).
- No route lets an MCP caller set or change an email address or any recipient.

### 4. Linker: `new_advisory` changes (`packages/linker/src/link.ts`)

- Built in `link.ts` (`packageRowsOf`), not in `packageWrites`, which stays package-only. The affected-backfill
  job calls `packageWrites` directly with no stored rows, so anything built there would fire for all history.
- Condition: the linker is writing a `package_advisories` row that did not exist before (no stored row), the
  record names at least one package, its status is `active`, and its `published` date is within 14 days of the
  run time. No fallback to `modified`: a record without `published` never fires.
- Row: `id` = `new_advisory:<vuln_key>`, `kind 'new_advisory'`, `entity_key` = the record's `vuln_key`,
  `new` = `<source>:<source_id>`, `source` = the source id. The fixed id plus the `changes` insert-ignore rule
  keeps only the first: retries, concurrent runs, and the same vuln from GHSA and OSV give one row.
- `first-load.ts` drops a record's `new_advisory` row whenever it drops that record's package rows (first-load
  mode, archive mode, over the cap). History loads never produce it.
- Count `new_advisory` rows in the linker's run stats.

### 5. Notify: package alerts (`apps/notify/src/*`)

- **Matching** (`match.ts`, new `matchPackages`): for each change whose kind is `new_advisory`,
  `newly_exploited`, `public_exploit`, `epss_band`, `fix_released` or `cvss_change`, find the packages it
  affects in `DB_ADVISORIES.affected` (by `(source, source_id)` from `new` for `new_advisory`, by `vuln_key`
  otherwise), at most 50 packages per change. Then find `watch_packages` rows with `alerts_on = 1` for those
  packages, in chunks of `D1_CHUNK`. A user's triggers are their `alert_triggers` plus `new_advisory` (a
  package watch exists to hear about new advisories). Queue with `via = 'pkg:<ecosystem>/<name>'`.
- Precedence: entry watch first, then package watch, then saved search. A change is queued once per user.
- **Plan** (`plan.ts`): `pkg:` rows count as watch rows for instant alerts, and go into digests like the rest.
- **Render** (`render.ts`): a package alert line names the package (from our `affected` row, already
  normalised) and the fixed version for that package: the lowest `fixed` across its ranges for this record,
  or "no fixed version yet". Links go only to MTI pages (the entry page and the watchlist page).
- **Subjects**: no text from any source. The single-item instant subject uses the entry ID or the package
  (`MTI: new advisory for PyPI/langchain`, `MTI: CVE-2026-1234 is exploited`), never a title. Multi-item and
  digest subjects stay as they are.
- **Per-user cap**: at most 50 items per email (already) and at most 5 instant emails per user per day; beyond
  that, items wait for the digest.
- **Watchlist change notices**: on each run, for users with `watch_events` rows where `notified_at IS NULL`
  and the oldest is at least 10 minutes old, send one email "Your MTI watchlist was changed" listing each change
  (action, package or entry ID, the client's host, time) and a link to the watchlist page; then set
  `notified_at`. At most one notice per user per hour. This email is sent even when alerts are off, to the
  account's email only. Count it in `email_sends` like the others.
- Delete `watch_events` rows older than 30 days.

### 6. MCP tools (`apps/mcp/src/tools/mti_watch_*.ts`, `shared.ts`)

- `ToolDef` gains `scope: 'mti:read' | 'mti:watch'` and `hints` (default the read-only set).
  `registerTool` uses them. `apiJson` gains `PUT`, `DELETE` and `PATCH`.
- New tool error codes: `limit_reached` ("You are watching the most packages allowed (200). Remove one
  first.") and `removal_limit` ("Too many watches were removed through MCP today. Try again later, or use the
  website.").
- Input for add and remove, one of:
  - `{ ecosystem, name }` (ecosystem from the canonical list, name up to 214 characters);
  - `{ purl }` (the version, if any, is ignored);
  - `{ entryId }` (a CVE, GHSA, OSV, MAL or EUVD ID, as `mti_get_entry` accepts).
  One item per call. No list input, so there is no bulk add or bulk remove.
- **`mti_watch_add`**: scope `mti:watch`; hints `readOnlyHint false, destructiveHint true, idempotentHint true,
  openWorldHint false`. Calls the PUT route. Returns `{ watched: { kind, ecosystem?, name?, entryId? },
  created, alerts: 'on' | 'off', notes }`.
- **`mti_watch_remove`**: scope `mti:watch`; same hints. Calls the DELETE route. Returns `{ removed }`.
- **`mti_watch_list`**: scope `mti:read`; read-only hints. Returns one `items` list, each with `kind: 'entry' |
  'package'`, newest first, fitted to the output budget and paged with the usual `{ o }` cursor.
- `mti_watch_add` and `mti_watch_remove` use `requireScopes('mti:read', 'mti:watch')` so the step-up challenge
  names both, and each `run()` also checks `deps.identity.scopes`. The pipeline's 403 for a missing `mti:read`
  (`auth/challenge.ts`) names `mti:read` plus every MCP scope the token already holds, so a client never loops
  between the two.
- Every tool name, description, title and schema follows the existing description linter and snapshot.
- A call from the report app or any other client surface is treated like any other call: same scope, caps
  and checks.

### 7. Elicitation when alerts are off (`apps/mcp/src/elicit.ts`)

- After a successful add, if the user's alerts are off (`alert_instant = 0` and `digest = 'off'`, read from
  `GET /v1/me`) **and** this request declared form elicitation in its client capabilities, answer with
  `input_required` and one form:
  - message: "Email alerts are off for your MTI account. Turn on an alert digest?" (fixed text, no URLs, no
    advisory or package text);
  - schema: `{ enable: boolean, frequency: 'daily' | 'weekly' }`, `enable` required.
- `requestState` is sealed with AES-GCM under a new secret `MCP_STATE_KEY` (not the HMAC secret). It binds:
  the user (`sub`), the tool name, a sha256 of the canonical arguments, an expiry 10 minutes out, and a random
  nonce. On the retry, refuse (tool error `invalid_argument`, field `requestState`) a state that fails to open,
  has expired, names another user or other arguments. Replaying a valid state is harmless (the PUT and the
  PATCH are idempotent), so it is not tracked.
- On accept with `enable: true`: `PATCH /v1/me` with the chosen digest; result `alerts: 'on'`.
- On decline, cancel, or `enable: false`: result `alerts: 'off'` with a note.
- A client that didn't declare elicitation gets the normal result with `alerts: 'off'` and a note: "Email
  alerts are off. Turn them on in MTI settings: <settings link>."
- The alert address always comes from the account. No form field can carry an address.
- `MCP_STATE_KEY` (and `MCP_STATE_KEY_NEXT` for rotation) are added to `checkConfig`, `.dev.vars.example` and
  the wrangler secrets comment.

## Tests

- Migration applies on a copy of the users schema.
- API: add, re-add (idempotent), list, remove; the 200 cap at the boundary (199 → 200 → 409), including two
  adds at once at 199; bad ecosystem; bad name; scoped npm and Maven names round-trip; another user's watch is
  never visible or removable; MCP callers write `watch_events`, website callers don't; the 20-removal cap
  (20th ok, 21st 429) for MCP only.
- `PATCH /v1/me` from MCP: digest daily/weekly accepted; `displayName`, `instant`, `digest: 'off'` and unknown
  fields refused with 403.
- Linker: first insert of a recent active advisory with packages writes exactly one `new_advisory`; an update
  writes none; an old record writes none; a withdrawn record writes none; the backfill path writes no
  `changes` rows.
- Notify: a `new_advisory` for a record affecting `PyPI/langchain` queues one row for a user watching it
  (`via pkg:PyPI/langchain`) and none for `alerts_on = 0`; a `newly_exploited` change on a vuln affecting a
  watched package queues for a user whose triggers include it; entry watch beats package watch; an instant
  email names the package and fixed version; subjects contain no source text (a title with markdown, a URL
  and an instruction stays out of the subject); the per-user instant cap; a watchlist change notice is sent
  once for several changes, even with alerts off, and not again within the hour.
- Tools: schemas and hints snapshot; `mti_watch_add` and `mti_watch_remove` with a token lacking `mti:watch`
  get the step-up challenge naming both scopes; `limit_reached` and `removal_limit` texts; one item per call.
- Elicitation: alerts off + elicitation declared → `input_required` with the fixed form; accept → digest on;
  decline and cancel → alerts stay off; no elicitation declared → note with the settings link; a tampered
  `requestState`, an expired one, one sealed for another user and one sealed for other arguments are all
  refused; the message and schema contain no URL and no package or advisory text.

## Not in scope

- Watching by version range, or watching a whole ecosystem.
- Webhooks, Slack or any delivery other than email.
- The listen stream (`subscriptions/listen`) and `GET /v1/me/changes`.
- Changing alert triggers from MCP.

## Acceptance criteria

1. `pnpm build` and the Workers tests pass; the lockfile is unchanged.
2. Package watches work through the API and the three tools, with the 200 cap and the MCP removal cap.
3. A new advisory for a watched package produces one alert (instant if the user has instant alerts, otherwise
   in the digest) naming the package and fixed version, with no source text in the subject.
4. The history backfill can't produce alerts.
5. Watch-changing tools need `mti:watch`; a token without it gets a step-up challenge.
6. Every watchlist change made through MCP reaches the user by email on the first notify run at least 10
   minutes after it (notify runs every 3 hours, so at most about 3 h 10 min).
7. Elicitation is used only when declared, asks only yes/no and a frequency, and a tampered or foreign
   `requestState` is refused.
8. After deploy, on staging (checked by hand, outside the loop): watching `PyPI/langchain` plus an injected
   test change produces one alert email and a digest entry.

## Decisions added at review

These sharpen the sections above. Where they differ, this section wins.

1. **Notify query budget.** Package matching uses at most 15 D1 queries per run, with no per-change package cap:
   - read the distinct watched set once:
     `SELECT DISTINCT ecosystem, name FROM watch_packages WHERE alerts_on = 1`
     (at most 20,000 rows; log `watch_set_large` if over);
   - read `affected` for the run's vuln keys and records in chunks of 90, and intersect in memory;
   - read users only for the hits.

   Eligibility is the same as `matchWatch`. An OS watch (`Debian`) matches `affected` rows stored with a
   release (`Debian:12`): match on the part before the first `:` as well as the exact ecosystem.
2. **Email budget.**
   - Watchlist change notices are sent first in each run. Alerts stop at 80 sends per day, leaving room under the
     95 daily cap.
   - Migration 0005 also rebuilds `email_sends` so its `kind` CHECK allows `watch_notice`, and `EMAIL_KINDS`
     gains it.
   - Suppressed, deleted or empty-email accounts are skipped.
3. **Per-user instant cap.**
   - Count today's instant emails per user as distinct `alerts_sent.sent_at` values since 00:00 UTC, and pass
     that map to `plan()`.
   - Over 5, items wait for the digest.
4. **Unsubscribe.**
   - Add scope `package` (item `ecosystem/name`), which sets `watch_packages.alerts_on = 0`.
   - Package-only instant emails use it. Mixed emails use `all`.
5. **Fixed versions in alerts.**
   - List up to 5 distinct `fixed` values for that package across the vuln's `affected` rows.
   - Order them with `@ti/core/versions` where that ecosystem has a comparator, else as stored.
   - Never "lowest by string".
6. **Removal cap is atomic.**
   - The DELETE carries `AND (SELECT COUNT(*) FROM watch_events WHERE user_id = ?1 AND action = 'remove' AND
     at > ?cut) < 20`.
   - The event row is inserted in the same batch, `WHERE EXISTS` the watch row.
   - A no-op (nothing to remove) writes no event.
   - The same applies to entry watches removed through MCP.
7. **Notice text is escaped and plain.**
   - The notice uses `render.ts` escaping. Every value is shown as text, never as a link, and cut to 100
     characters.
   - The client is shown as "app (self-reported): <host>", and only when the `client_id` is an https URL.
   - The subject is fixed: "Your MTI watchlist was changed".
   - A package-alert subject takes the name from the user's `watch_packages` row, and only if it matches
     `^[A-Za-z0-9@/._:-]{1,100}$`. Otherwise it says "a watched package".
8. **API contract the tools rely on.**
   - Entry watch `PUT` adds `created` to its answer. Entry watch `DELETE` answers `{ ok: true, removed }`. Both
     changes are additive, so the website is unaffected.
   - `apiJson` reads the JSON error body on 404, 409 and 429, and maps:
     - `not_found` → new tool error `not_found` ("MTI has no entry with that ID.")
     - `limit_reached` → `limit_reached`
     - `removal_limit` → `removal_limit` (with Retry-After)
     - any other 429 → `rate_limited`
9. **Elicitation mechanics.**
   - "Declared" means a 2026-07-28 request whose `clientCapabilities.elicitation` has `form`, or is `{}`.
   - Never elicit on a 2025-era request. Set the SDK's `inputRequired` legacy shim off.
   - Don't use the SDK's `requestState.verify` hook (it answers -32602). Open the state inside the tool, so a
     bad state gets the tool error the spec names.
   - The state carries `created` and the target, so the retry skips the PUT and reports the original `created`.
   - Validate the answer against the form schema. `frequency` defaults to `daily`.
   - Watch tools never become tasks. No tool output contains the account's email address.
10. **Missing state key.**
    - `MCP_STATE_KEY` is not added to `checkConfig`. That would turn every MCP request into a 503 wherever the
      secret is missing.
    - If the key is missing, never elicit: log `mcp_state_key_missing` and return the note with the settings
      link.
    - The key is set on staging before this merges.
11. **Account deletion.** Add `watch_events` to `deleteUserData` (`delete-user.ts`) and its test.
12. **Verified email only.**
    - `webhooks-clerk.ts` stores only a verified address (the primary one first), else `''`.
    - Today it falls back to `email_addresses[0]` without checking that it is verified.
13. **Landing order and shared files.**
    - This change lands after the skills and Tasks changes, then rebases and regenerates the tool-list,
      tools-hash and instructions snapshots.
    - `ToolDef` gains optional `scope?: 'mti:read' | 'mti:watch'` (default `mti:read`) and
      `hints?: Partial<typeof HINTS>` (merged over `HINTS`). The Tasks change adds the same two fields.
    - In `registerTool`, `scope: 'mti:watch'` means `requireScopes('mti:read', 'mti:watch')`.
    - `ToolErrorCode` gains `limit_reached`, `removal_limit` and `not_found`. Edits to `shared.ts` only add
      union members, these fields and the `apiJson` mapping.
    - Don't touch `instructions.ts`: the skills change writes the watch-tool lines.

## Changes from the first build (round 2)

An independent review of the first build found the items below. Fix all of them on the same branch. Migration
`0005` hasn't been applied anywhere outside loop sandboxes, so edit it in place rather than adding `0006`.

1. **One user can't clog the queue** (blocker). Today `loadQueue` reads the oldest 5,000 rows across all users,
   and each email deletes only the 50 items it sends.
   - Cap queued rows per user at 200. When matching would go over, drop the excess and count it.
   - Load the queue per user: at most the 50 newest rows per user, using a window function. So one user's
     backlog can't fill the read for everyone.
   - Each email holds up to 50 items in this order: entry-watch items, then package items, then saved-search
     items, newest first within each group. If more were queued, end with one line: "and N more updates on
     your watchlist" (a link to the watchlist page).
   - Every queued row an email covers, shown or counted, is deleted when that email is sent.
2. **Matching order and budget.**
   - Match `new_advisory` records first, then other kinds.
   - Late rows already queued or sent for that user aren't matched again.
   - If the package-match query budget runs out, stop the forward cursor after the last change whose matching
     finished. The rest are matched on the next run, never skipped.
   - Process hits in change order, not in sorted package order, so the same packages don't always lose.
3. **Only real packages can be watched.**
   - `PUT /v1/me/watch/packages/...` checks `DB_ADVISORIES.affected` for at least one row for that package. For
     OS ecosystems, the ecosystem is matched before its first `:`.
   - If there is none: 404 `unknown_package`. The tool error text is "MTI has no records for that package yet,
     so it can't be watched."
   - The distinct watched-set read gets `ORDER BY ecosystem, name`, and its cap rises to 50,000 rows, with the
     log line.
4. **Email budget split.**
   - Notices have their own budget: at most 20 a day in all, and at most 2 per user per day. Pending events carry
     over to the next run.
   - Alerts have the rest: at most 75 a day, so the total stays within 95.
   - Pick notice users by the oldest pending event (`watch_events_pending` index), not by user id.
   - Drive the notice query from that index, not a scan of all users.
5. **No attacker text that looks like something else.**
   - `clean()` also strips Unicode format characters (category Cf), including bidi controls and zero-width
     characters.
   - In notices and alerts, a package name or entry ID is shown only if it matches `^[A-Za-z0-9@/._:-]{1,100}$`.
     Otherwise it reads "a package (see your watchlist)".
   - A fixed version is shown only if it matches `^[A-Za-z0-9.+~:_-]{1,40}$`. Otherwise it is left out.
   - Any shown value whose last dot is followed by 2 or more letters is written with that dot as `[.]`
     (`verify-mti[.]com`), so mail clients don't turn it into a link. Client hosts are always written this way.
6. **Verified email everywhere.**
   - `getClerkUser` in `apps/api/src/lib/clerk-api.ts` (used by `loadOrCreateUser`) applies the same
     verified-only rule as the webhook: add `verification` to its schema.
7. **First-load never announces.** `first-load.ts` drops `new_advisory` rows in every mode, not only the modes
   that drop package rows.
8. **Package info lookups are linear.**
   - `loadPackageInfo` queries `affected` by `vuln_key` only (the indexed column), in chunks, and filters names
     in memory.
   - No nested chunk loops.
9. **Instant cap counts instant emails only.**
   - Add `instant_counts (user_id, day, n)` to migration 0005, with primary key `(user_id, day)`.
   - Increment it for each instant email sent, and read it for the cap.
   - Delete rows older than 2 days.
   - Don't scan `alerts_sent` for this.
10. **Webhook safety.**
    - `user.created` for a user row that already exists doesn't overwrite the email.
    - When a stored non-empty address is cleared because no verified address remains, log `email_cleared` (warn,
      no address in the log).
    - Existing unverified rows are not backfilled.
11. **Small fixes from the loop's own review.**
    - The `remove` event names the entry key actually deleted. Write one event per removed key.
    - The rest of that review is covered by item 9.

## Round 3: bring the branch up to date

`main` has moved: the skills change (#61) and the Tasks change (#62) have merged. Rebase `feat/mcp-watch` onto
the latest `origin/main` and resolve the conflicts:

- `SPEC.md`: take this branch's version.
- `apps/mcp/src/tools/shared.ts`:
  - `ToolDef` already has optional `scope` and `hints` from the Tasks change. Keep one definition.
    `scope: 'mti:watch'` must still mean `requireScopes('mti:read', 'mti:watch')`.
  - Keep both sets of `ToolErrorCode` members.
- `apps/mcp/src/mcp.ts`, `server.ts`, `env.ts`, `config.ts`, `.dev.vars.example`, `wrangler.jsonc`: keep both
  sides.
- Tests:
  - remove the watch-tool skips in the "INSTRUCTIONS names every enabled tool" test (the lines exist now);
  - regenerate the tool-list and tools-hash snapshots.

Then run the full build and Workers tests again, and confirm that the watch tools still never become tasks.

## Round 4: up to date again

The `tasks-polish` change (#63) has merged since round 3, and it changes `mti_deep_query`'s input schema. Rebase
`feat/mcp-watch` onto the latest `origin/main`:
- take this branch's `SPEC.md`;
- regenerate the tool-list snapshot by running only that test with `-u`, so that the list has all twelve tools
  in `TOOL_ORDER`, and rename the test to say twelve;
- then run the full build and Workers tests.

No other code changes.

## Round 5: fixes from the re-review

An independent re-review confirmed that most of round 2 is fixed. It found the items below; fix all of them.
MTI runs on Workers Paid, so the D1 limit is 1,000 queries per invocation. Still keep notify's query count small
and bounded.

1. **The "known package" check must not scan** (blocker).
   - Today `PUT /v1/me/watch/packages/...` runs a query that scans every row of an OS ecosystem (`Ubuntu:*`)
     before answering. One account could run up reads and cost.
   - Add a new advisories migration, `0003_affected_by_name.sql`: `CREATE INDEX affected_by_name ON affected
     (name, ecosystem);`.
   - The check becomes one indexed seek: `WHERE name = ?2 AND (ecosystem = ?1 OR (ecosystem > ?1 || ':' AND
     ecosystem < ?1 || ';')) LIMIT 1`.
   - Test with `EXPLAIN QUERY PLAN` that it uses `affected_by_name` with `name=?`, never a range scan of the
     primary key.
2. **The queue window and cap respect item class.**
   - The per-user window orders by class first (entry watch, then package watch, then saved search), then
     newest first. The "and N more" cut and the delete of covered rows use the same order.
   - At the 200-row cap, a new watch or package row evicts the user's oldest saved-search row. Only saved-search
     rows are dropped at the cap, never watch rows; if a user has 200 watch rows, the oldest watch row goes.
3. **Package matching without chunk caps.**
   - Use one statement for the `affected` lookup and one for the watcher lookup per run, each with
     `IN (SELECT value FROM json_each(?1))` (or a json_each join), so the bound-parameter limit no longer forces
     chunks or a 135-package cap.
   - Look up watchers from the hit packages only. Remove the global watched-set read and its 50,000 cap.
   - Match forward rows in `(at, id)` order, so the matched set is always a prefix. Store a lower bound for the
     late read with the cursor, so late rows can't age out unmatched.
   - If any cap remains, log `package_match_truncated` with counts, never names.
4. **No redundant reads.** Remove `queueable`'s pre-reads. The INSERT already enforces the cap and the
   `alerts_sent` check with `OR IGNORE`. Read notice events in one query.
5. **Every dot is defanged.**
   - In shown package names and IDs, every dot followed by a letter becomes `[.]` (`/\.(?=[A-Za-z])/g`).
   - In client hosts, every dot does.
6. **Notice priority.** Pick notice users in this order:
   - users with a pending `remove` or `digest_on` event first;
   - then users with the fewest notices in the last 24 hours;
   - then the oldest pending event.

   So a burst of other accounts can't delay the notice for a removal.

Tests:
- the index plan test;
- class order in the window and at the cap;
- one change touching 500 watched packages queues them all;
- a late row survives a busy run;
- `Go/verify-mti.com/reset.v2` and `mti.com.evil.io` are fully defanged;
- a removal notice goes ahead of 30 other pending notices.

## Round 6: fixes from the round-5 review

1. **The known-package check is two exact seeks** (`watch-packages.ts`).
   - Today's OR form seeks on `name` only, so `PUT …/npm/linux` reads every `linux` row across `Debian:*` and
     `Ubuntu:*`.
   - Use `SELECT EXISTS(SELECT 1 FROM affected WHERE name = ?2 AND ecosystem = ?1) OR EXISTS(SELECT 1 FROM
     affected WHERE name = ?2 AND ecosystem > ?1 || ':' AND ecosystem < ?1 || ';')` (or an equivalent UNION ALL
     with LIMIT 1).
   - The plan test asserts both `(name=? AND ecosystem=?)` and `(name=? AND ecosystem>? AND ecosystem<?)`.
   - A test with many `linux` rows in other ecosystems shows the check reads none of them (use `.scanstats`-style
     row counts if available, else the plan).
2. **No permanent skip from the late bound** (`collect.ts`, `match.ts`). The late read starts at the earlier
   of:
   - the stored lower bound;
   - the usual floor, `start.at` minus 6 hours.

   A row whose `at` falls between the floor and the bound is always read again. Test: a change committed late,
   with `at` between the floor and the bound, is matched on the next run.
3. **Bounded `affected` reads; a failure never stalls alerts** (`match.ts`).
   - Query `affected` in ordered chunks of about 100 keys or records, and stop when the pair budget is spent.
     The rest is "unmatched" and deferred by the prefix rule.
   - Never hold more than the budget in memory.
   - Replace per-row array copies (`[...arr, r]`) with push.
   - Catch a failed package-matching query: log `package_match_failed` and carry on with entry-watch and
     saved-search matching. Hold the cursor only for package matching, so one bad run can't stop all alert
     email.
   - Test: a run whose `affected` rows exceed the budget defers the rest, and the next run picks them up. A
     thrown `affected` query still sends entry-watch alerts.
4. **"And N more" only for fully loaded windows** (`consume.ts`, `plan.ts`, `send.ts`). Set `coversBefore` only
   when that user's whole window was loaded under the global row limit. Otherwise send the loaded rows and
   leave the rest queued.
5. **Notice query index.** Add `CREATE INDEX watch_events_by_user_pending ON watch_events (user_id,
   notified_at);` to migration 0005 (not applied anywhere yet, so edit it in place).
6. **Defang `://` too.** In shown values, write `://` as `[:]//`, so `http://10.0.0.1/x` is never a link.

Don't run `git fetch` or `git push`; the branch stays local to the sandbox.

## Round 7: simpler package matching

Rounds 2, 5 and 6 added a budgeted matcher: a held forward cursor, a late lower bound and a prefix rule. Each
review found new edge cases in it: skipped changes, stalls, re-sends after 30 days, and rows silently dropped by
a `LIMIT`. Replace it with a simpler design that always finishes a run.

1. **Put `collect.ts` back** to its behaviour on `main`: the forward cursor and the 6-hour late window, with no
   stored lower bound and no held cursor. The cursor always advances past every change a run reads.
2. **Package matching per run, with no budget, prefix or hold** (`match.ts`):
   - From the run's changes, take the vuln keys (kinds `newly_exploited`, `public_exploit`, `epss_band`,
     `fix_released`, `cvss_change`) and the `(source, source_id)` records of `new_advisory` changes.
   - Read affected packages with `SELECT DISTINCT` of the key, the base ecosystem (the part before the first
     `:`, or the whole value) and the name. Use `WHERE vuln_key IN (SELECT value FROM json_each(?1))`, and the
     same for records through `affected_by_record`. Use chunks of at most 200 keys, every chunk in the same run.
     DISTINCT collapses distro releases (`Ubuntu:20.04`, `Ubuntu:22.04` → `Ubuntu`), so kernel CVEs give a few
     rows, not hundreds. No `UNION` with `LIMIT`.
   - Look up watchers for the resulting `(base ecosystem, name)` pairs through `watch_packages_by_package`, with
     json_each, in chunks. A watch on `Debian` matches `Debian:12` because pairs use the base ecosystem.
   - Hard cap per run: 50,000 distinct pairs. Past it, stop reading more chunks, log
     `package_match_truncated` with counts (never names), and carry on. Changes past the cap get no package
     alerts. Nothing is held or retried.
   - Any error in package matching: log `package_match_failed` and skip package alerts for this run. Entry-watch
     and saved-search matching, planning and sending go ahead, and the cursor advances.
   - Remove the matched/unmatched bookkeeping, `lateFull`, the bound, and the related cursor fields. Old cursor
     JSON with extra fields still parses.
3. **`loadPackageInfo` can't stop sends** (`consume.ts`).
   - Wrap it in try/catch. On failure, use an empty map: the line names the package and says "fixed version: see
     MTI".
   - Bound it: per planned item, read `SELECT DISTINCT fixed` for that `(vuln_key, base ecosystem, name)` with
     `LIMIT 5`, batched with json_each. Never read every `affected` row of a vuln.
4. **Keep everything else from rounds 2–6:**
   - the class-ordered queue window and cap;
   - `coversBefore` only for full windows;
   - notices and their priority and index;
   - defanging;
   - the two-seek known-package check;
   - verified email;
   - `instant_counts`;
   - first-load dropping `new_advisory`.

Tests:
- Delete the tests that only exercised the hold, bound and prefix logic.
- 100 kernel CVEs × 300 Ubuntu/Debian rows plus one npm CVE in one run: the npm watcher is queued, and the
  kernel CVEs give one pair per base ecosystem.
- A run past the pair cap logs and advances.
- An `affected` read that throws still sends entry-watch alerts, and the cursor advances.
- A `loadPackageInfo` that throws still sends every planned email, including ones with `pkg:` items.
- An OS watch on `Ubuntu` matches `Ubuntu:22.04` rows.
- Re-running the same window doesn't send duplicates (the `alert_queue` key and `alerts_sent`).

Don't run `git fetch` or `git push`.

## Round 8: last fixes from the round-7 review

The round-7 design is sound. Fix these and change nothing else.

1. **`loadPackageInfo` uses the vuln index** (`consume.ts`, around line 194).
   - Today SQLite picks `affected_by_name` for OS ecosystems and reads every row of that package in that OS.
   - Write the name filter as `+name = ?3` (or use `INDEXED BY affected_by_vuln`), so the plan is
     `affected_by_vuln (vuln_key=? AND ecosystem…)`.
   - Order fixed versions, so the five shown are deterministic: `ORDER BY fixed`.
   - Add "and more" when there are more than five.
   - Add a plan test that asserts `affected_by_vuln` for both an npm item and an `Ubuntu` item.
2. **`new_advisory` records first.** In `matchPackages`, read the record chunks (from `new_advisory` changes)
   before the vuln-key chunks, so at the pair cap the new advisories are kept. Delete `matchOrder` if nothing
   else needs it.
3. **Bounded queue inserts.**
   - While building inserts, keep at most `MAX_QUEUED_PER_USER` rows per user in memory, in class order: entry
     watch, then package, then saved search.
   - Split the inserts into batches of at most 500 statements.
   - Save the cursor in the last batch, after every insert, so a failure before it simply retries the window.
     Inserts are idempotent through the `alert_queue` key.
4. **Tests.**
   - Run the kernel test with `maxPairs: 3`, and assert no truncation (DISTINCT collapses the releases).
   - Add a test that a round-6 cursor JSON with a `late` field parses and is saved without it.
   - Add a test that 1,000 watchers × 500 changes stays within the per-user cap and inserts in bounded batches.

Don't run `git fetch` or `git push`.
