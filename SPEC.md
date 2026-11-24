# home-latest: the home page shows what is new, and empty sections say why

## Why

The home page (`apps/web/app/routes/home.tsx`) shows a hero, a search box, type buttons without counts and a
"Browse by type" block. On production it looks empty. The approved mock-up
(`research/threat-data-system/board/platform.html`, function `home()`) had count tiles and live panels:
"Exploited in the wild, latest", "Recent breaches", "What changed today" and "Browse by type" with counts.
The owner wants the top 10 latest items of each kind on the landing screen.

Sections with no records yet (AI incidents, cyber operations, techniques on a new environment) show a search
empty state, "No matching incidents. Try fewer words.", which reads as broken.

## What to build

1. **One home API call.** `GET /v1/home` on ti-api returns, in one response cached like other public routes
   (`cachedPublic`, a few minutes):
   - `counts`: records per type (vulnerabilities, exploited in the wild, public exploits, breaches,
     AI incidents, cyber operations, malicious packages, techniques).
   - `lists`: up to 10 items each, newest first: `exploited` (newest exploited-in-the-wild signal),
     `vulnerabilities` (newest published), `exploits` (newest public exploit or proof-of-concept),
     `breaches` (newest notice), `aiIncidents`, `maliciousPackages`. Each item: key, title, type, the date
     that orders it, and the one signal that makes it notable (for example "KEV 22 Nov", "Exploit-DB").
   - `changes`: up to 10 most recent changes across types (what changed and when), from the data the API
     already keeps (signals and advisory updates); if no change log exists, newest signals are enough.
   Queries must use indexes and stay well inside D1 limits; prefer small, separate `LIMIT 10` queries. Add the
   response type to `@ti/core` API types.
2. **Home page.** Render the mock-up's structure with real data: hero and search as today, count tiles that
   link to their lists, then the panels above in a responsive grid. Each panel has a "See all" link to the
   matching filtered list. A panel with no items is left out, and a tile with zero shows "0" with a quiet
   "loading" or "coming soon" note (see 3). Use existing components and tokens; do not restyle the app (a
   redesign is planned separately).
3. **Honest empty states.** Lists and type pages whose type has no records at all (not "no match for this
   query") say so plainly, for example "No AI incidents yet. The sources for this section are being
   connected." with a link to `/sources`. Keep "No matches, try fewer words" for queries that filter a
   non-empty list.
4. **Tests.** API: `/v1/home` shape, limits, ordering, cache header, empty database. Web: home renders the
   panels from a fixture, leaves out empty ones, and the "no records yet" state on incidents.

## Not in scope

The visual redesign, new dependencies, migrations unless an index is missing for these queries (then add one
`NNNN_name.sql`), collector and source changes (another loop owns them), `pnpm-lock.yaml`.

## Files this loop owns

`apps/api/src/routes/` (a new home route and its registration), `apps/api/src/lib/` (query helpers for it),
`apps/api/test/`, `packages/core/src/api.ts`, `packages/db/migrations/` (index only, if needed),
`apps/web/app/routes/` (home and the list routes' empty states), `apps/web/app/components/`,
`apps/web/app/data/` (including fixtures), `apps/web/app/styles/app.css` (only for the new panels),
`apps/web/test/`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. The tests in section 4 pass.
3. QA in the browser against the fixtures: the home page shows count tiles and at least the exploited,
   vulnerabilities and breaches panels; the incidents page with no data shows the "no records yet" state.

## Changes from the first build of this branch

The first round was blocked only by `pnpm test:workers`: the web smoke check (`apps/web/scripts/smoke.mjs`)
failed four checks on `/sign-in` and `/sign-up`. That was a fault on `main`, not in this branch: a sign-in
fix added `https://cdn.protect.clerk.com` to the page security policy without updating the smoke check's
allowed hosts. `main` now has that fix (commit 07a94ac).

1. `git fetch origin && git rebase origin/main`, resolving any conflict in favour of keeping both changes.
2. Re-run `pnpm build` and `pnpm test:workers`; both must pass.
3. Do not change `apps/web/scripts/smoke.mjs` or `apps/web/app/lib/security.server.ts`.
