# mti-brand: the product is MTI, the Motiontic Threat Index, at mti.motiontic.com

## Why

The product has a name and a home. It is **MTI**, short for **Motiontic Threat Index**, and production is
served at `https://mti.motiontic.com`. The app, its emails and its docs still say "Threat Index", and the
production web Worker has no custom domain.

## What to build

1. **One place for the name.** Add the product names to `@ti/core` (short name `MTI`, full name
   `Motiontic Threat Index`) and use them everywhere a person reads the name. Today the string "Threat Index"
   is hard-coded in the web app (`apps/web/app/lib/seo.tsx`, `root.tsx`, `components/shell.tsx`,
   `lib/security.server.ts`, the route files), the emails (`apps/notify/src/render.ts`), the unsubscribe page
   (`apps/api/src/lib/unsubscribe.ts`) and the watchdog report (`apps/collector/src/report.ts`).
2. **How the name reads.**
   - Header brand: `MTI`, with "Motiontic Threat Index" as the accessible name and on the home page's main
     heading or lede.
   - Page titles: `<page> · MTI`; the home page title is `MTI: Motiontic Threat Index`.
   - Footer: `MTI, the Motiontic Threat Index. Code under Apache-2.0; …` (keep the rest of the line).
   - Emails: subjects start `MTI:`; the footer line is `MTI, the Motiontic Threat Index`. The sender display
     name comes from the deploy variable and is not changed here.
   - Open Graph and JSON-LD site name: `Motiontic Threat Index`.
   - Sentences that use the name in running text say "MTI" after the first full mention on a page.
3. **Custom domain for production web.** In `apps/web/wrangler.jsonc`, the top level (production) gets
   `"routes": [{ "pattern": "mti.motiontic.com", "custom_domain": true }]`. Staging keeps workers.dev only.
   Check that `apps/web/scripts/deploy-web.mjs` and the Vite build pass the route through, and that its tests
   still pass.
4. **Canonical origin.** Canonical links, the sitemap, `robots.txt`, Open Graph URLs and links in emails must
   use the configured site URL (`TI_APP_URL` / `APP_BASE` / `SITE_ORIGIN`), never the request host, so
   production pages point at `https://mti.motiontic.com` even when reached on workers.dev. Fix any place that
   does not. A request to the production Worker on its workers.dev host for a page route redirects (301) to
   the same path on the configured site URL when one is set; staging never redirects.
5. **Clerk production instance.** Production will use a Clerk production key whose frontend API is
   `clerk.mti.motiontic.com`. Confirm the CSP built in `apps/web/app/lib/security.server.ts` and the Clerk
   setup derive the frontend API host from the publishable key and work with that host, and add a test with a
   `pk_live_` key that decodes to `clerk.mti.motiontic.com`.
6. **Docs.** `README.md`, `apps/web/README.md`, `docs/architecture.md` and the opening of
   `docs/IMPLEMENTATION_PLAN.md` introduce the product as "MTI (Motiontic Threat Index)". The repository name,
   package names (`@ti/*`), Worker names (`ti-*`), database names, the `ThreatIndex/0.1` User-Agent and code
   identifiers do not change.
7. **Tests.** Update every test that asserts the old name. Add tests for: the title format, the email subject
   prefix, the canonical origin rule and the workers.dev redirect (production only).

## Not in scope

Renaming packages, Workers, databases, queues, buckets or the repository. New pages. Design changes beyond the
name. `scripts/smoke-staging.mjs` and `apps/web/app/routes/index-az.tsx` are being changed by another loop:
in `index-az.tsx` change only a hard-coded name string if there is one, and do not touch the smoke script.
Do not touch `pnpm-lock.yaml`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. `grep -rn "Threat Index" apps packages` shows only "Motiontic Threat Index" (through the shared constant or
   in comments), with any exception listed and explained in the proof.
3. The production web config carries the custom domain route; the staging config does not.
4. QA in the browser: the header shows MTI, a page title ends `· MTI`, and the footer line is as specified.
