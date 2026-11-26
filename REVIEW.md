# REVIEW.md

What gstack-loops' reviewer should care about in this repo. It reads this file on every review,
headless or in `/gloop-build`. Keep it short. When the same finding keeps coming back, add a line
here (or a lint rule) rather than paying for another review cycle.

## What failure looks like here

- A licence gate is bypassed: data from a source that is off, link-only or unlicensed gets stored or
  shown (`packages/core/src/licence.ts`, the source registry and the per-source files in
  `packages/sources/src/sources/`, the API's display modes).
- A secret, account ID, KV namespace ID or Clerk key lands in the repo or in logs. Wrangler configs
  keep `${VAR}` placeholders; real values live in `.env`, `.dev.vars` or Wrangler secrets.
- Account code reads `orgId` or assumes Clerk Organizations. Accounts are single-user, keyed by `userId`.
- A webhook is accepted without signature verification, or processed twice (dedupe on `svix-id`).
  Routes for webhooks, `/unsubscribe` and `/internal/jobs/*` (`apps/api/src/routes/`) must check their
  signature or token before anything else, including while they are still `501` stubs (`lib/auth.ts`).
- D1 writes skip the budget meter (`reserveWrites`) or go one row at a time instead of in batches;
  a Worker invocation does unbounded work.
- A migration that may already be applied is edited instead of adding a new one.
- Personal data (emails, user IDs) appears in logs, or deleting an account leaves user rows behind.
- A queue- or cron-only Worker gets a public HTTP route.

## MCP

The MCP server (`apps/mcp`, served at `/mcp`) hands data to AI agents. Treat it as an untrusted-input
boundary in both directions.

- The user's token never leaves `ti-mcp`. Calls to `ti-api` go through `callApi` (`apps/mcp/src/api.ts`)
  with a signed assertion (`packages/core/src/mcp-user.ts`); nothing from the client's request is copied.
- Every source-derived string is cleaned before it reaches an agent (titles, summaries, names, URLs).
- Nothing logs tool arguments, package lists or tokens.
- Tool descriptions are fixed text with no instructions to the model.
- A new API route used by MCP needs an entry in `MCP_ROUTES` (`apps/api/src/lib/mcp-routes.ts`) with its
  scope. Routes not listed there are refused for MCP, and an MCP identity never has admin rights.

## Do not nitpick

- Formatting and naming that Biome already enforces.
- Style preferences with no effect on behavior.

## Ignore

- `pnpm-lock.yaml`, generated `apps/*/wrangler.deploy.jsonc`, test fixtures under `fixtures/`.

## How to report

- Every finding names a file and a line. Never guess a filename.
- Start with a summary that gives the count, or says exactly "no issues".
