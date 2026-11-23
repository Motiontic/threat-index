# launch-hardening: rate limits, error pages, request ids, security headers, `/ops` and a staging smoke

## Why

Everything a visitor can reach is merged: the public API, the web app with Clerk sign-in, alerts, deep queries
and the world pages. Nothing stops one client from making thousands of requests a minute, a 429 or 5xx has no
friendly page, logs cannot follow one request from `ti-web` into `ti-api`, the operator has no view of run
health or budgets, and the security headers differ between the two apps. This change adds what launch needs
(plan §8 "Caching and limits", §11, §14; milestone M7): per-IP and per-user rate limits, 429/5xx pages and JSON
errors with `Retry-After`, a request id carried from web to API in structured logs, an admin-only `/ops` page, a
staging smoke script, and one set of security headers across both apps.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| Limits | None, except `POST /v1/deep-query`: 10 per user per hour and one active job, counted in `ti_control.jobs` (`DEEP_RATE_PER_HOUR`), 429 with `retry-after` |
| API app (`apps/api/src/index.ts`) | `health` mounted first, `clerkMiddleware()` on `/v1/*`, then route modules. No `onError`/`notFound`; `guarded()` in `lib/cache.ts` turns failures into `500 { error: 'internal' }` and logs a bare string. `cachedPublic` keys the cache on a route-built path only. No security headers except on `/unsubscribe` (own CSP, `no-referrer`, `nosniff`) |
| API config | `wrangler.jsonc` has `ADMIN_USER_IDS: ""` in both envs, but `Bindings` (`lib/env.ts`) does not declare it. Producers: `LOAD` only |
| Web (`apps/web`) | `workers/app.ts` → React Router; `entry.server.tsx` sets `BASE_HEADERS` + nonce CSP (`frame-ancestors 'none'`) via `lib/security.server.ts`; `.data` responses get the base set; redirects get them in `secureRedirect`. No HSTS anywhere. Resource routes (`sitemap.xml`, `account/do`) get nothing. `public/_headers` sets only `nosniff` for assets |
| Web → API | `data/api.server.ts` is the only `fetch`; public calls carry no visitor header, account calls carry only `Authorization: Bearer`. Any non-200/404/400 becomes `ApiUnavailable` → `bridge()` → 502. Root `ErrorBoundary` has copy for 404, 502 and "something went wrong" |
| Ops data | `ti_control`: `runs` (status, `error` starting `dead-lettered after 6 attempts:` for DLQ'd steps), `jobs` (E2B, `source_id` holds the **user id** for `deep-query`), `budget` (`d1_writes`; `emails_sent` is never written). Emails sent today live in `ti_users.email_log(day, sent)`. `CADENCE_MS` lives in `apps/collector/src/planner.ts` |
| Smoke | `apps/web/scripts/smoke.mjs` checks the built web app locally; nothing checks a deployed staging |
| Cloudflare docs (Nov 2026) | Rate limiting binding: `ratelimits: [{ name, namespace_id: "<integer>", simple: { limit, period: 10 \| 60 } }]`, not inherited into `env.staging`; `env.X.limit({ key })` → `{ success }`; counts are per Cloudflare location and approximate; bindings sharing a `namespace_id` share counters. Wrangler 4.166 in the lockfile accepts it; Miniflare implements it. GA on Workers Paid, which this deploy uses |

## What to build

This change may edit `apps/api/**`, `apps/web/**`, `packages/core/src/**`, `apps/collector/src/planner.ts` (one
import), `scripts/` and `.dev.vars.example` files. No migration. No new dependency. Do not refactor existing
route error shapes; add to them.

### 1. Shared helpers in `@ti/core`

- `packages/core/src/cadence.ts`: move `CADENCE_MS` here; `planner.ts` re-exports it so collector code is unchanged.
- `packages/core/src/log.ts`:
  ```ts
  export const REQUEST_ID_HEADER = 'x-request-id';
  export function requestIdFrom(raw: string | null): string; // keeps /^[A-Za-z0-9-]{8,64}$/, else crypto.randomUUID()
  export function safeFields(f: Record<string, unknown>): Record<string, string | number | boolean | null>;
  export function logEvent(level: 'info' | 'warn' | 'error', event: string, f?: Record<string, unknown>): void;
  ```
  `logEvent` writes one `JSON.stringify({ level, event, ...safeFields(f) })` line. `safeFields` keeps only
  primitives, drops keys matching `/email|token|secret|password|authorization|cookie|signature|ip$/i`, replaces
  any string that contains an email address with `"[redacted]"`, and cuts strings to 200 characters.
- `packages/core/src/edge.ts` (export `hmac` and `constantTimeEqual` from `sign.ts` instead of copying them):
  ```ts
  export const CLIENT_IP_HEADER = 'x-ti-client-ip', CLIENT_TS_HEADER = 'x-ti-client-ts', CLIENT_SIG_HEADER = 'x-ti-client-sig';
  export const CLIENT_SKEW_SECONDS = 60;
  export function signClientIp(secret: string, ip: string, ts: number, requestId: string): Promise<string>;
  // hex(HMAC-SHA256(secret, `client-ip\n${ip}\n${ts}\n${requestId}`))
  export function verifiedClientIp(secret: string | undefined, h: Headers, now?: Date): Promise<string | null>;
  export function ipKey(ip: string): string; // IPv4 as is; IPv6 cut to its first four hextets (a /64)
  ```
  `verifiedClientIp` fails closed: no secret, a missing header, a bad timestamp, skew over 60 s, an IP that is
  not IPv4/IPv6 text, or a wrong signature → `null`.
- `packages/core/src/ops.ts`: `OpsReport` (below), `parseAdminIds(raw?: string): string[]` (comma list, trimmed,
  each `^user_[A-Za-z0-9]{1,64}$`, at most 20, others dropped) and `isAdmin(ids, userId?)`. Empty list → no admin.

### 2. Rate limits

Bindings (top level and again in `env.staging`, with different `namespace_id`s so staging never shares prod
counters):

| App | Binding | Key | Limit | prod / staging namespace |
| --- | --- | --- | --- | --- |
| ti-api | `RL_PUBLIC` | `ip:<ipKey>` | 120 / 60 s | `7101` / `7201` |
| ti-api | `RL_USER` | `u:<userId>` | 240 / 60 s | `7102` / `7202` |
| ti-api | `RL_DEEP` | `u:<userId>` | 5 / 60 s | `7103` / `7203` |
| ti-web | `RL_PAGES` | `ip:<ipKey>` | 120 / 60 s | `7104` / `7204` |

- `apps/api/src/lib/rate-limit.ts`: `clientIp(c)` = `verifiedClientIp(EDGE_HMAC_SECRET, headers)` ??
  `CF-Connecting-IP` ?? `null`. `rateLimit` middleware on `/v1/*` (after Clerk) and `/unsubscribe`: signed in →
  `RL_USER`; else `RL_PUBLIC` by IP. With no IP (a service-binding call without a valid signature) the per-IP
  check is skipped and `rate_limit_no_client` is logged once per isolate, so a missing secret never throttles the
  whole site into one bucket. `POST /v1/deep-query` also calls `RL_DEEP` before the existing hourly check, which
  stays. `/v1/health`, `/webhooks/*` and `/internal/*` are not limited (signed or trivial).
- A missing binding or a throwing `limit()` fails open and logs `rate_limit_unavailable`. No KV/D1 fallback.
- The limit runs before `cachedPublic`, so cache hits count. The new headers never enter a cache key.
- 429 body: `{ error: 'rate_limited', retryAfter: 60, requestId }`, headers `Retry-After: 60`,
  `Cache-Control: no-store`.
- Web: `workers/app.ts` checks `RL_PAGES` by `CF-Connecting-IP` before the router (assets never reach the
  Worker). Over the limit → a static 429 HTML page (no script, no external asset, "Too many requests. Wait a
  minute and try again." and a link home) with `Retry-After: 60`, the security headers, a CSP of
  `default-src 'none'; frame-ancestors 'none'` and `X-Robots-Tag: noindex`; a `.data` request gets a plain 429.
- Web → API: `createSiteData` and `createAccountClient` take a `ClientContext { requestId; ip: string | null }`.
  Every call sends `x-request-id`, and, when `EDGE_HMAC_SECRET` is set and `ip` is known, the three
  `x-ti-client-*` headers. Public calls still send no Cookie, Authorization, User-Agent or other visitor header.
  `getData(request)` and `getAccount(args)` build the context from the request (`x-request-id` set by
  `workers/app.ts`, `CF-Connecting-IP`). Update the existing "no visitor header" tests to this allow-list.
- Secret `EDGE_HMAC_SECRET` on both Workers; add it to both `.dev.vars.example` files and the wrangler comments.

### 3. Errors: JSON and pages

- API `app.onError` → 500 `{ error: 'internal', requestId }`, logged as `unhandled_error` with the error name
  only; `app.notFound` → 404 `{ error: 'not_found', requestId }`. `guarded()` logs through `logEvent` with the
  request id and route. Existing route error bodies are unchanged; all error responses get `Cache-Control: no-store`.
- Web: `api.server.ts` maps 429 to a new `ApiRateLimited(retryAfter)` (from `Retry-After`, 1–3600, default 60);
  `bridge()` turns it into `data(null, { status: 429 })`, and account actions do the same. `workers/app.ts` adds
  `Retry-After: 60` to any 429 lacking one. Root `ErrorBoundary` gets copy for 429 ("Too many requests" / "Wait a
  minute and try again."), 500 and 503 ("Something went wrong on our side"), keeping 404 and 502. Error pages
  stay `noindex` and show no stack outside dev.

### 4. Request ids and logs

- API middleware `lib/request-context.ts`, first in `index.ts`: `requestId = requestIdFrom(x-request-id)`, set
  on `c` and on every response; after `next()` one `logEvent('info', 'request', { requestId, method, route:
  routePath(c, -1) /* hono/route pattern, never the raw path or query */, status, ms, userId?, limited? })`.
- Web `workers/app.ts`: always a fresh id (a visitor's `x-request-id` is replaced), set on the request passed
  to the router and on the response; one `request` line with method, pathname (≤ 120 chars, no query), status, ms.
- Never logged: emails, tokens, cookies, IPs, query strings, bodies, signatures, secrets. `deep-query` and
  `unsubscribe` logging keep their current rules.

### 5. `/ops`

- API `routes/admin-ops.ts`: `GET /v1/admin/ops`. Not signed in, or `userId` not in
  `parseAdminIds(env.ADMIN_USER_IDS)` → 403 `{ error: 'forbidden' }` (the same answer for both). Never cached
  (`private, no-store`), per-user limit applies, logs `admin_ops_viewed` with the user id.
- `lib/ops.ts` `buildOpsReport(env: OpsEnv, now: Date): Promise<OpsReport>`, D1 reads in one
  `DB_CONTROL.batch()` plus one `DB_USERS` read:
  ```ts
  interface OpsReport {
    generatedAt: string;
    sources: { id: string; cadence: string; ingest: boolean; lastSuccess: string | null;
      lastRun: { status: string; startedAt: string } | null; failed7d: number; deadLettered7d: number; late: boolean }[];
    budget: { day: string; d1Writes: number; d1Limit: number; emailsSent: number; emailCap: number;
      queueOps: number; r2ClassA: number };
    queues: { name: 'ti-jobs' | 'ti-jobs-dlq' | 'ti-load'; backlog: number | null; oldest: string | null }[];
    jobs: { byStatus: Record<string, number>; recent: { id: string; kind: string; status: string;
      sourceId: string | null; createdAt: string; finishedAt: string | null; error: string | null }[] };
    deadLetters: { runId: string; sourceId: string; finishedAt: string | null; error: string }[];
  }
  ```
  Sources: every registry entry; `ingest` via `canIngest` and the KV override; `late` = ingest on and no success
  within 2 × `CADENCE_MS`. Budget: today's `budget` row and `email_log.sent` (not `budget.emails_sent`).
  Queues: add producer bindings `JOBS` (`ti-jobs`) and `JOBS_DLQ` (`ti-jobs-dlq`) to ti-api in both envs,
  used only for `metrics()`; each call has a 1 s timeout and gives `null` on failure. Jobs: counts by status over
  7 days and the 20 newest; `sourceId` is `null` for `deep-query` (it is a user id); `error` cut to 200 chars.
  Dead letters: the 20 newest `runs` whose error starts with `dead-lettered`.
- Web `routes/ops.tsx` (`route('ops', …)` before `*`): signed out, or not in the web's own
  `parseAdminIds(env.ADMIN_USER_IDS)` → the 404 page without calling the API; API 403 → 404 as well. Renders
  with the existing `Panel`/`Table`/`Chip`: budgets (with a meter), queues, sources (late and failing first),
  dead letters, E2B jobs. `noindex`, `Cache-Control: private, no-store`. Guard `data/ops-guard.ts` copies known
  fields and caps lists (sources 200, jobs 20, dead letters 20). Fixtures mode: `fixture-account.server.ts`
  answers `/v1/admin/ops` with an invented report for fake users (the web's list still gates it).
- `ADMIN_USER_IDS`: no ids in the repo. ti-api uses `"${TI_ADMIN_USER_IDS?}"` in both envs; ti-web gets it as
  a `--var` from `deploy-web.mjs` (env `TI_ADMIN_USER_IDS`), like the Clerk publishable key. Add to `Bindings`/`Env`.

### 6. Security headers

- API `lib/headers.ts`, set on every response **only when the route has not set the header** (so `/unsubscribe`
  keeps its CSP): `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src
  'none'; frame-ancestors 'none'`, `Permissions-Policy` as the web's. No `preload` (a domain-wide commitment).
- Web: add the same HSTS to `BASE_HEADERS`; `workers/app.ts` applies the non-CSP base set to every response
  that lacks it (resource routes, 429); `public/_headers` gives assets HSTS, nosniff, `Referrer-Policy`,
  `X-Frame-Options` and `Permissions-Policy`.

### 7. Staging smoke: `scripts/smoke-staging.mjs`

`node scripts/smoke-staging.mjs --web <url> --api <url>` (or `TI_WEB_URL`/`TI_API_URL`). Exports
`runSmoke(fetchImpl, { web, api })` and runs only when executed directly. Sequential, at most 40 requests. Web:
`/`, `/search?q=log4j`, one `/e/<key>` (first hit of `/v1/search?q=log4j`, "skip" when none), `/index`,
`/index/a`, `/sources`, `/breaches`, `/incidents`, `/techniques`, `/sign-in`, a missing page (404), `/ops`
(404). API: `/v1/health`, `/v1/search?q=log4j`, `/v1/entries/<key>`, `/v1/index/a`, `/v1/sources`,
`/v1/breaches`, `/v1/incidents`, `/v1/techniques`, `/v1/me` (401), `/v1/admin/ops` (403), an unknown path (404
JSON). Each row checks status, `x-request-id`, HSTS, nosniff, frame protection (`frame-ancestors` or `DENY`),
`Referrer-Policy`, and `Permissions-Policy` on web, plus JSON content type on API. Prints a
`check | status | result` table and exits 1 on any fail. No credentials, no writes.

### 8. Tests

- `apps/api/test/launch.workers.test.ts`: fake `RL_*` bindings via `app.request(path, init, env)`: 429 body,
  `Retry-After`, per-IP vs per-user key, signed IP honoured, forged/expired signature ignored (falls back to
  `CF-Connecting-IP`), no IP → no limit, missing binding fails open, health not limited, deep limit before the
  hourly one; one test that the real Miniflare `RL_PUBLIC` binding exists and returns `success`. Errors: unknown
  path 404 JSON, a throwing route 500 with `requestId`. `x-request-id` kept when valid, replaced when not.
  Headers on JSON, 404, 429, health and `/unsubscribe` (its CSP intact). `/v1/admin/ops`: anonymous and
  non-admin 403, admin 200 with seeded runs, jobs (deep-query `sourceId` null), dead letters, budget and
  `email_log`, `no-store`. A console spy shows no email, token, IP or query string in any log line.
- `packages/core`: `log.test.ts`, `edge.test.ts` (round trip, skew, wrong secret, IPv6 key), `ops.test.ts`.
- `apps/web/test/launch.test.ts`: client headers (allow-list, signature verifies, none without secret), 429 →
  `ApiRateLimited` → 429, `RL_PAGES` page with headers, headers on document, `.data`, redirect and resource
  responses, `/ops` loader (signed out, non-admin, API 403 → 404; admin calls `/v1/admin/ops` with Bearer).
- `test/smoke-staging.test.ts` (Node): `runSmoke` with a fake fetch, one passing run and one failing header.
- `apps/web/scripts/smoke.mjs`: add `/ops` (404) and an HSTS check on every page.

## Not in scope

KV/D1 fallback limiter, WAF rules, per-route tuning, a global (non per-location) limit, DLQ-age alert emails,
`/ops` actions (retry, switch a source), R2/queue-op metering (shown as recorded), Logpush, HSTS preload, a
privacy policy page.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass; output in `proof/launch-hardening/build.txt` and `workers.txt`.
2. Over-limit API calls get 429 JSON with `Retry-After`; over-limit pages get the 429 page (tests).
3. A web request reaches the API with a verifiable signed IP and the same request id; a forged header is
   ignored (tests); public calls still carry no Cookie or Authorization.
4. `/v1/admin/ops` is 403 for anonymous and non-admin callers and never cached; `/ops` is 404 for them (tests).
5. Both wrangler files declare the `ratelimits` bindings in both envs with distinct namespaces (test).
6. No log line holds an email, token, IP or query string (test).
7. Every API and web response type carries HSTS, nosniff, frame protection and `Referrer-Policy` (tests).
8. QA: run `ti-api` (`wrangler dev`, port 8716, local D1 with a few seeded runs and jobs) and `ti-web` (port
   8715, `--var DATA_SOURCE:fixtures --var TI_ENV:local --var AUTH_MODE:fake --var ADMIN_USER_IDS:user_admin`),
   save screenshots of `/ops` as the fake admin and the 429 page (from a throwaway copy of the built web config with `RL_PAGES` at `limit: 1`), and
   the `smoke-staging.mjs` table run against the two local ports to `proof/launch-hardening/`.
9. The PR lists what is left: the not-in-scope items, and setting `EDGE_HMAC_SECRET` and `TI_ADMIN_USER_IDS`
   on staging and production before launch.
