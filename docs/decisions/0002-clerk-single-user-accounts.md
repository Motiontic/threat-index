# 0002. Clerk for sign-in, single-user accounts only

- Status: accepted
- Date: 2026-11-22

## Context

Visitors can search and preview freely. A free account opens full records, a watchlist, alerts and saved searches. We want a ready-made, secure sign-up with no passwords to manage, and as little personal data as possible.

## Decision

- **Clerk** handles sign-up and sign-in with an email verification code, Google and GitHub. Passwords are off.
- **Single-user accounts only.** Clerk Organizations stay disabled, and the code never reads `orgId`. There are no teams, invites or roles in v1.
- **The API Worker verifies Clerk's session token on every request** (`@hono/clerk-auth`). It returns preview-only fields to visitors, so the gate is enforced on the server, not just blurred in the UI.
- **Clerk webhooks** (`user.created`, `user.updated`, `user.deleted`) keep the `ti_users` database in step. They are verified with `verifyWebhook` and de-duplicated by `svix-id`.
- **Admins** are listed by Clerk user ID in `ADMIN_USER_IDS`, not by org role.

## Consequences

- No credentials are stored by us.
- Teams, SSO and shared watchlists would need Organizations later, and this ADR would be revisited.
