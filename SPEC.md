# accounts-web: Clerk sign-in in the web app, the sign-up gate, and the account pages

## Why

The account routes are live in `ti-api` (`/v1/me`, `/v1/me/watch`, `/v1/me/saved-searches`, `DELETE /v1/me`), and
`/v1/entries/:id` already answers `access: 'full'` to a signed-in caller. The site still has no sign-in: `/account`
says "Accounts aren't open yet", the gate card links to it, and locked tabs are disabled buttons. This change adds
Clerk (`@clerk/react-router`) to `ti-web` per plan §9: sign-in and sign-up, the gate on entry pages, "return to
intent" for locked actions, the full entry view with evidence kept apart by kind, and `/account` with profile and
alert settings, watchlist, saved searches and account deletion. Public pages stay cache-safe: the visitor's session
is forwarded to `ti-api` only for account calls and the full entry view.

This branch edits only `apps/web/**` and `pnpm-lock.yaml`. It adds one dependency, `@clerk/react-router`.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `@ti/core/account` | `Me`, `MePatch`, `AlertSettings` (`instant`, `digest: 'daily'\|'weekly'\|'off'`, `digestWeekday` 0–6 UTC), `WatchItem`, `WatchListResponse`, `SavedSearch`, `SavedSearchParams`, `SavedSearchCreate`, `SavedSearchListResponse`, `DeleteAccountResponse`, limits `MAX_WATCH_ITEMS` 1000, `MAX_SAVED_SEARCHES` 50, `MAX_DISPLAY_NAME_CHARS` 80, `MAX_SAVED_SEARCH_NAME_CHARS` 80 |
| API account routes | `GET/PATCH/DELETE /v1/me`; `GET /v1/me/watch`, `PUT /v1/me/watch/:id` (body `{ alertsOn? }`, 409 `limit_reached`), `DELETE /v1/me/watch/:id`; `GET/POST /v1/me/saved-searches`, `DELETE /v1/me/saved-searches/:id` (UUID). All `requireUser` → 401 `sign_in_required`; `no-store`. **No route changes a saved search's `alertsOn`** |
| API auth | `clerkMiddleware()` from `@hono/clerk-auth` on `/v1/*`; reads `userId` only. A request with `Authorization: Bearer <Clerk session token>` is signed in. Signed-in entry reads skip the shared cache |
| `@ti/core/api` | `EntryFull` = preview + `cwe`, `advisories` (`display: full\|link\|hidden`, `url`, `affected`), `signals` (`kind`, `source`, `ref`, `firstSeen`, `url`), `changes` |
| `app/data/api.server.ts` | The only `fetch`. Sends `Accept` only (no Cookie, no Authorization), 5 s timeout, 2 MiB cap, guards every body. `guardEntryResponse` cuts a full body to preview fields |
| `app/data/data.server.ts` | `getData(request)` never reads `request`. Fixtures mode uses `fixtureApi` (no `/v1/me*` routes) |
| `app/lib/security.server.ts` | CSP: `script-src 'self' 'nonce-…'`, `connect-src 'self'`, `style-src/img-src/font-src 'self'`, `frame-ancestors 'none'`. Documents and `.data` get `Cache-Control: private, no-cache` |
| Routes | `/account` placeholder; `/e/:id` with `GateCard` (links to `/account`) and disabled locked tabs; shell rail "Sign up free" / "Log in" link to `/account` |
| `scripts/smoke.mjs` | Fails on `type="password"` and `method="post"` in any page; `--mode fixtures` (8710) and `--mode api` (8711, `scripts/stub-api`) |
| `wrangler.jsonc` | Vars `TI_ENV`, `DATA_SOURCE`; no Clerk names. React Router 8.5.2, React 19.3.1, compat date 2026-11-01 with `nodejs_compat` |

## What to build

### 1. Dependency and configuration

- Add `@clerk/react-router` at an exact version whose peer range covers `react-router ^8.3` and `react ~19.3`
  (3.7.9 at the time of writing; use the newest such release at least two weeks old, and record it in the PR).
- Keys come from the Worker env at request time, never from the bundle: `CLERK_PUBLISHABLE_KEY` is a plain var
  (public), `CLERK_SECRET_KEY` a Worker secret. With compat date ≥ 2025-04-01 and `nodejs_compat`, `process.env`
  carries both; confirm the installed SDK reads them there, otherwise pass them from `env` (`cloudflare:workers`)
  into `clerkMiddleware({ publishableKey, secretKey })` and say why in the PR.
- `wrangler.jsonc`: add no key values. Add a comment naming `CLERK_PUBLISHABLE_KEY` (var, set at deploy) and
  `CLERK_SECRET_KEY` (secret). Add `apps/web/.dev.vars.example` listing both names with dummy values.
- `scripts/deploy-web.mjs`: pass `--var CLERK_PUBLISHABLE_KEY:<value>` to `wrangler deploy`, read from
  `TI_CLERK_PUBLISHABLE_KEY_STAGING` or `TI_CLERK_PUBLISHABLE_KEY` (env or repo `.env`). Refuse to deploy when it is
  missing, when production gets a `pk_test_` key, or when the built config has an `AUTH_MODE` var (§7).
- `app/lib/clerk-config.server.ts`: `clerkConfig(env): { publishableKey: string; frontendApi: string } | null`.
  Decodes the key (`pk_(test|live)_` + base64 of `<host>$`); the host must match `^[a-z0-9.-]+$` and end in
  `.clerk.accounts.dev` (test) or start with `clerk.` (live). Missing secret, missing key or a bad key → `null`:
  Clerk is off, every page renders signed out, and the sign-in buttons read "Sign-in is unavailable" (fail closed;
  public pages keep working).
- Never read `orgId`, `orgRole`, `orgSlug` or any organization API. A test greps `apps/web/app` for `org[A-Z]` and
  `organization`.

### 2. Server auth seam: `app/lib/auth.server.ts`

- Root: `export const middleware` runs Clerk's `clerkMiddleware()` only when `clerkConfig(env)` is non-null (else a
  no-op). The root `loader` returns `rootAuthLoader(args, () => ({ ...today's fields, clerk: config | null }))`.
- `getSession(args): Promise<{ userId: string; token: string } | null>`: from Clerk's `getAuth(args)`, `userId` and
  a fresh `getToken()`; `null` when signed out, Clerk is off or the token is missing. The one place that touches
  Clerk on the server, so tests and fake mode swap it.

### 3. Data seam: forward auth only where needed

- `api.server.ts` stays the only `fetch`. Add `createAccountClient(api, token)` returning:
  `me()`, `patchMe(MePatch)`, `watchList()`, `watch(id, alertsOn?)`, `unwatch(id)`, `savedList()`,
  `saveSearch(SavedSearchCreate)`, `deleteSearch(id)`, `deleteAccount()`, `entryFull(id)`. Each sends
  `Authorization: Bearer <token>` and `Content-Type: application/json` for bodies, never `Cookie`, never any visitor
  header. Same timeout, cap and guards. 401 → `SignInRequired`; 409 → `ApiConflict(error)`; 400 → `ApiBadRequest`;
  404 → `null` (or `NotFound` for mutations); else `ApiUnavailable`.
- New guards in `guards.ts`: `guardMe`, `guardWatchList`, `guardWatchItem`, `guardSavedList`, `guardSavedSearch`,
  `guardEntryFull`. They copy fields; links pass only when `http:`/`https:`; advisories with `display: 'hidden'` are
  dropped and `link` ones keep only source, id and URL.
- `data.server.ts`: add `getAccount(args)` → `{ session, client } | null` (the only reader of `env.API` stays this
  file). `getData(request)` and every public method keep sending no auth — the public cache never sees a session.
- `entryFull` returns `null` when the API still answers `access: 'preview'`; the page then shows the preview.

### 4. Client auth: `app/lib/auth.tsx`

- Wraps Clerk so pages never import it: `<AuthProvider>` (real: `ClerkProvider` with `loaderData`,
  `signInUrl="/sign-in"`, `signUpUrl="/sign-up"`, the page `nonce`, and `appearance` from
  `app/lib/clerk-appearance.ts`), `useAuthState(): { isLoaded, isSignedIn }`, `useOpenSignUp()`,
  `<WhenSignedIn>`, `<WhenSignedOut>`, `<AccountButton>` (Clerk `UserButton`). Use `SignedIn`/`SignedOut` if the
  installed version exports them, else `Show when=…`.
- Appearance: Geist, ink `#121212`, canvas `#FAFAF8`, accent `#EF7D45`, radius from `tokens.css`; a test checks the
  values match `tokens.css`.
- Top bar and rail: signed out → "Sign up free" (`/sign-up`) and "Log in" (`/sign-in`); signed in → "Account"
  (`/account`) and the user button.
- Routes `sign-in/*` and `sign-up/*`: full-page `<SignIn routing="path" path="/sign-in">` /
  `<SignUp routing="path" path="/sign-up">`, `noindex`. Our code renders no password field anywhere; sign-in methods
  (email code, Google, GitHub; passwords off) are set in Clerk's dashboard, not in code.

### 5. Gate and return to intent

- Entry page, signed out, Clerk loaded: call `openSignUp({ fallbackRedirectUrl: location.href })` once per entry
  visit (a ref keyed on `entry.key`; not again on re-render or revalidation). Closing it leaves the preview usable.
  `GateCard` buttons open the modal instead of linking to `/account`.
- `app/lib/intent.ts`: `saveIntent(i)`, `takeIntent(): Intent | null` over `sessionStorage` key `ti:intent`. `Intent`
  = `{ action: 'watch', target: entryKey } | { action: 'save-search', target: searchQueryString } |
  { action: 'tab', target: `${entryKey}#${tab}` }` plus `at` (ms). `takeIntent` clears first, then validates shape,
  length (≤ 600 chars) and age (≤ 30 min); anything else → `null`. Storage errors are swallowed.
- Locked actions (Watch, Save search, locked tabs) signed out: save the intent, open the modal. When
  `isSignedIn` turns true: `revalidate()`, then run the taken intent once (watch → submit; save-search → submit with
  the query as the name; tab → select it). Pages show a short status ("Watching CVE-…").

### 6. Account actions and pages

- Resource route `account/do` (action only; loader 405). Every request: `Origin` must equal the request origin
  (else 403); no session → 401 JSON. Form field `intent` ∈ `profile | watch | unwatch | watch-alerts | save-search |
  delete-search | delete-account`, each validated (ids by the entry id pattern or UUID, names ≤ 80 chars without
  control characters, weekday 0–6, digest enum). Returns `{ ok: true, ... } | { ok: false, error }`. Mutations use
  fetchers (`useFetcher`), so signed-out pages still contain no `method="post"` markup.
- `/account` loader: no session → redirect `/sign-in?redirect_url=%2Faccount`. Else load `me`, `watchList`,
  `savedList` in parallel (401 → same redirect; unavailable → 502). `noindex`. Tabs by `?tab=`:
  - **profile**: display name; instant alerts on/off; digest daily/weekly/off; weekday (shown only for weekly).
  - **watch**: entries with title and link, alerts toggle (`watch-alerts`), remove; count against the limit.
  - **saved**: name, query and filters, "Run" link to `/search?…` rebuilt from the stored params, delete. The alerts
    state shows read-only with "Changing alerts on a saved search is coming soon" (no API route yet).
  - **delete**: explains what is removed; the button stays disabled until the field holds exactly
    `delete my account`; the action re-checks that text, calls `deleteAccount()`, and on success the client signs
    out and goes to `/?deleted=1` (a one-line notice). A 502 from the API shows "Your data is deleted; removing the
    sign-in failed, try again" and keeps the button.
- Entry page signed in: a Watch / Watching button (state from `watchList`), the locked tabs become real tabs
  (`?tab=`): **Evidence**, **Advisories**, **Changes**. Evidence keeps four labelled groups and never merges them
  into one score: *Exploited in the wild* (`exploited_wild`, `ransomware`, KEV date), *Public exploit code*
  (`public_exploit`, `poc`; metadata and links only), *Detections* (`detection`), *Prediction* (EPSS, labelled as a
  probability, not evidence). Unknown kinds go under "Other signals". Advisories honour `display`. Changes list newest
  first. The JSON-LD and meta stay preview-only.
- Search page: a "Save search" button (signed in → `save-search`; signed out → intent + modal).

### 7. Fake auth for tests and QA

- `AUTH_MODE=fake` is honoured only when the data mode is `fixtures` **and** `TI_ENV=local`; otherwise it is ignored
  and logged once. In fake mode Clerk is not loaded; `getSession` reads an `HttpOnly; SameSite=Lax` cookie
  `ti_fake_user` set by route `__fake/sign-in?as=<a-z0-9>{1,20}` (404 outside fake mode) and cleared by
  `__fake/sign-out`; the client provider is a context with the same hooks, and "sign up" goes to the fake route.
- `fixture-api.server.ts` gains in-memory `/v1/me*` routes accepting only `Bearer fake.<user>`, mirroring the real
  status codes and limits, and returns `access: 'full'` entries (with signals of every kind) to that token.

### 8. CSP

`buildCsp(nonce, { dev, clerk })`: with a Clerk config add exactly `https://<frontendApi>` to `script-src` and
`connect-src`, `https://challenges.cloudflare.com` to `script-src` and `frame-src` (bot protection), `https://img.clerk.com`
to `img-src`, `worker-src 'self' blob:`. No wildcards. Pass the nonce to `ClerkProvider`; if Clerk's injected styles
still need it, add `'unsafe-inline'` to `style-src` only and say so in the PR. Without a config, the CSP is today's.
`frame-ancestors 'none'` stays.

### 9. Tests (`apps/web/test/`, Vitest, no network)

`clerk-config`, `security` (CSP with and without config, no `*`), `account-client` (Bearer sent, no Cookie, status
mapping, guards drop `javascript:` links and hidden advisories), `data` (public calls never carry Authorization even
when a session exists), `account-action` (Origin check, 401, each intent's validation, typed confirmation), `intent`
(expiry, bad shapes, storage throwing), `evidence` (grouping by kind, EPSS apart), `fake-auth` (ignored unless
fixtures + `TI_ENV=local`), `deploy-web` (refuses missing key, `pk_test_` on production, `AUTH_MODE`), `no-org` grep.
Smoke: add `/sign-in` and `/sign-up` (200, no password input), `/account` signed out → 302 to `/sign-in`; in
`--mode api` pass a dummy test publishable key and secret and check the CSP names that host and nothing wider.

### 10. QA

The sandbox has no Clerk keys and cannot sign into a Clerk instance, so QA proves the UI in fake mode and proves the
Clerk wiring by tests and the CSP. Run the built app with `wrangler dev` on port 8712, `--var DATA_SOURCE:fixtures
--var TI_ENV:local --var AUTH_MODE:fake`. Save screenshots to `proof/accounts-web/`: entry signed out (gate), click
Watch signed out then fake sign-in → watched (return to intent), entry signed in (Evidence tab with the four groups),
each account tab, toggles changed and persisted after reload, delete flow (button disabled, then enabled by the typed
text, then the `/?deleted=1` notice), `/search` Save search. Also one screenshot of `/sign-in` with Clerk off
("Sign-in is unavailable"). Record the console for CSP violations (none expected).

## Not in scope

- Toggling alerts on a saved search (needs `PATCH /v1/me/saved-searches/:id` in the API; shown read-only).
- Export, data export as JSON, receipts, `/ops` admin page, email preferences beyond the four settings.
- Clerk dashboard settings and webhooks; any change outside `apps/web/**` and the lockfile.
- A live sign-in check against Clerk: done on staging after deploy (see the ops note).

**Ops note (not code):** before deploying, set the web secret once per worker with
`wrangler secret put CLERK_SECRET_KEY --name ti-web-staging` (and `--name ti-web` for production). It must be the
same Clerk instance's key that `ti-api-staging` uses, or the API will reject forwarded tokens. Put the publishable key
in `TI_CLERK_PUBLISHABLE_KEY_STAGING` / `TI_CLERK_PUBLISHABLE_KEY` for `deploy-web.mjs`. After the staging deploy,
sign in with an email code and check the browser console for CSP violations (Clerk may need `*.protect.clerk.com`).

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass; output saved to `proof/accounts-web/build.txt` and `workers.txt`.
2. `@clerk/react-router` is pinned exactly; the lockfile changes only for it and its dependencies.
3. With no Clerk config, every public page renders as today (smoke unchanged) and sign-in says it is unavailable.
4. Public data calls never carry `Authorization` or `Cookie`, signed in or not (test).
5. Account calls and `entryFull` carry only `Authorization: Bearer` (test).
6. `/account/do` rejects a foreign `Origin` (403) and a missing session (401) (test).
7. The CSP adds only the instance host, `challenges.cloudflare.com` and `img.clerk.com`; no wildcard (test + smoke).
8. No page renders a password field; `apps/web/app` never reads an organization field (tests + smoke).
9. Fake auth works only with fixtures and `TI_ENV=local`; `deploy-web.mjs` refuses a build with `AUTH_MODE` (test).
10. The gate opens once per entry visit; a locked action taken signed out completes after sign-in (QA screenshots).
11. Evidence shows exploited, public exploit, detections and prediction as separate groups (test + screenshot).
12. Profile, watchlist and saved-search changes persist across reload; account deletion needs the typed text and
    ends signed out (QA screenshots).
13. The PR lists what is left: saved-search alert toggle (API), export, live Clerk check on staging.
