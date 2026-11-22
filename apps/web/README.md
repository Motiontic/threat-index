# apps/web

The Threat Index web app: React Router v7 in framework mode, server-rendered on Cloudflare Workers. It is built in milestone M1 (public pages) and M2 (accounts). See `docs/IMPLEMENTATION_PLAN.md` §9.

## Plan

- **Scaffold** with the official Cloudflare template (`pnpm create cloudflare@latest web --framework=react-router`), then add the package to the workspace.
- **Routes:** `/`, `/search`, `/e/:id`, `/index/:letter?`, `/sources`, `/account` (profile, watch, alerts, saved). Full-page `/sign-in/*` and `/sign-up/*` act as fallbacks.
- **Data:** loaders call `ti-api` through a service binding (`API`). Entry previews render on the server for search engines.
- **Auth:** `@clerk/react-router`, with `rootAuthLoader` in the root loader and `ClerkProvider` at the root. **Single-user accounts:** Organizations are off and the app never reads `orgId`.
- **Sign-up gate:** for signed-out visitors, an entry page shows the preview and calls `clerk.openSignUp({ fallbackRedirectUrl })` once per entry. Locked actions (Watch, Save search, Export, locked tabs) are stored in `sessionStorage` and finished once `isSignedIn` turns true.
- **Look:** the Motiontic tokens (Geist, ink `#121212`, canvas `#FAFAF8`, accent `#EF7D45`), applied to Clerk through its `appearance` settings. The UI follows the clickable mock-up on the design board (`platform.html`).
