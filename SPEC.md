# privacy-page: a privacy page for MTI that says exactly what the code stores

## Why

MTI has accounts, email alerts, watchlists, saved searches, an MCP server with sign-in, long-running Tasks and
deep queries, but no privacy page. People signing up, and the Claude connector directory, need one. It must be
accurate: every statement on it has to match what the code actually does today.

## Current state (on main)

- `apps/web/app/routes/` has no privacy route. The site menu links "Terms" (check whether a terms page exists, and
  link the privacy page next to it).
- Data the code stores, to be verified and completed from the code itself:
  - D1 `ti_users`: `users` (Clerk user ID, email, display name, alert settings), `watch`, `watch_packages`,
    `saved_searches`, `alert_queue`, `alerts_sent`, `email_log`, `email_sends`, `webhook_events`, `package_usage`,
    `mcp_blocks`, `watch_events`, `instant_counts`, `notify_state`;
  - D1 `ti_control.jobs` (deep queries: owner, template, parameters, status) and the R2 results under the job prefix;
  - MCP Tasks: per-user Durable Object storage, deleted 90 minutes after creation (70 for deep queries);
  - request logs (ti-api, ti-mcp, ti-web, notify) and what each logs (ti-mcp never logs `sub` or client ID; check
    ti-api);
  - `deleteUserData` (`apps/api/src/lib/delete-user.ts`): what account deletion removes, and what stays.
- Third parties that process data: Clerk (sign-in), Resend (email), Cloudflare (hosting, logs, D1, R2), E2B (deep
  query sandboxes: query parameters only), Google (only if the user signs in with Google). Check for any analytics,
  error tracking or fonts loaded from third parties, and list them too.

## What to build

1. A route `/privacy` in `apps/web` using the site's normal page layout, linked from the footer and from wherever
   "Terms" is linked. It is served on staging and production like other pages, with no sign-in.
2. Plain-English sections:
   - Who runs MTI and how to reach us;
   - What we collect, and why;
   - What we don't collect: MTI never asks for source code, files or secrets; the MCP tools take package names and
     versions only;
   - How long we keep each thing;
   - Who processes data for us;
   - Email alerts and how to stop them;
   - The MCP server and AI clients: what an AI client sends, Tasks results kept 90 minutes, nothing used for
     training;
   - Deleting your account, and what remains;
   - Cookies (Clerk session cookies; anything else found);
   - Changes to this page.
3. Every factual statement must match the code. PROOF.md has a table: one row per statement, with the file and line
   that proves it. If the code and a statement disagree, change the statement, never the code.
4. Placeholders for decisions only the owner can make, written exactly as `[[OWNER: …]]`:
   - legal name of the operator;
   - postal or contact address;
   - governing law;
   - the privacy contact email (use `TI_CONTACT_EMAIL` if that is the intended address, and still mark it for
     confirmation);
   - minimum age;
   - how long account data is kept after deletion, if the code doesn't already settle it.

   A test fails if any `[[OWNER:` placeholder is still present when `TI_ENV` is `production`, so the page can't
   ship to production unfinished. On staging, placeholders render visibly highlighted.
5. A "Last updated" date. No tracking scripts, no third-party assets on the page.

## Tests

- The route renders on the web smoke with the footer link.
- The placeholder guard fails in production mode while any `[[OWNER:` remains.
- The PROOF.md table covers every section.

## Not in scope

- Terms of service text, cookie banners, consent management, a data export feature.

## Acceptance criteria

1. `pnpm build` and the Workers tests pass; the lockfile is unchanged.
2. `/privacy` is linked from the footer and renders on staging.
3. Every statement has a code reference in PROOF.md, and owner-only decisions are clearly marked placeholders.
4. The page can't go to production with placeholders left.
