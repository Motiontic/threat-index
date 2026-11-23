# Threat Index

An open-source system that keeps **one record of every public vulnerability, exploit, breach and AI incident**. It pulls 55 public sources, checks them for changes every 3 hours, and traces every fact back to the exact record it came from.

It runs on **Cloudflare's free plan** (Workers, D1, R2, Queues, KV). Heavy jobs, such as big files, the first load and deep history, run in **E2B sandboxes**. Accounts use **Clerk** (single-user, no organisations), and alert emails go through **Resend**.

> **Status: pre-alpha (milestone M0).** The design and plan are complete; the code is a scaffold. See [the implementation plan](docs/IMPLEMENTATION_PLAN.md).

## What it does

- **Search** CVEs, packages, companies, techniques and terms. Search and previews are open to everyone.
- **Entry pages** merge every source for one flaw, breach or incident:
  - exploit evidence, with _exploited in the wild_, _public exploit_ and _prediction_ kept separate;
  - affected versions;
  - timeline;
  - related entries;
  - **receipts** for every fact.
- **Free accounts** open full records, a per-user **watchlist**, **email alerts** (daily digest by default) and **saved searches**.
- **Licence-aware by design.** Every source has an on, off or link-only switch, and every page shows the credit line of each source it used.

## How it works

```
Cron ─► collector ─► asks each source "anything new?" ─► fetches only new items
          ├─ small updates ─► D1 (hot set)        receipts ─► R2 raw/
          └─ big or rare files ─► E2B sandbox (DuckDB) ─► R2 lake/ (full history) + inbox/
inbox/ ─► loader ─► D1 (within the free daily write budget)
changes ─► notify ─► Resend (alerts)
web (React Router SSR) ─► api (Hono, Clerk auth) ─► D1 + R2
```

- Every source fits one of seven pull patterns: `git`, `changelist`, `since`, `fingerprint`, `feed`, `page` and `heavy`.
- D1 holds only the **hot set**: CVEs from 2024 on, plus anything exploited, with a public exploit or with EPSS ≥ 0.1. The full history lives as Parquet files in R2.

## Repository layout

| Path                | What                                                            |
| ------------------- | --------------------------------------------------------------- |
| `apps/collector`    | Cron + queue consumer: planner, pull patterns, linker, watchdog |
| `apps/loader`       | Moves E2B output into D1 within the daily write budget          |
| `apps/notify`       | Matches changes to watchlists and sends alerts with Resend      |
| `apps/api`          | Hono JSON API, Clerk auth, webhooks, internal job callbacks     |
| `apps/web`          | React Router v7 server-rendered web app                         |
| `packages/core`     | Types, ID normalisation, licence gates, budget meter            |
| `packages/sources`  | The 55-source registry                                          |
| `packages/patterns` | The seven pull patterns                                         |
| `packages/parsers`  | One parser per data format                                      |
| `packages/linker`   | Alias graph, hot-set rule, change log, company matching         |
| `packages/db`       | SQL migrations for the six D1 databases                         |
| `e2b/`              | E2B sandbox template and heavy jobs                             |
| `docs/`             | Implementation plan, decisions (ADRs), guides                   |

## Quick start (local)

Prerequisites: Node 22, pnpm 10, a Cloudflare account. E2B, Clerk and Resend accounts are only needed for the parts that use them.

```bash
pnpm install
cp apps/api/.dev.vars.example apps/api/.dev.vars    # fill in your own keys
pnpm --filter @ti/db migrate:local                   # create local D1 tables
pnpm dev                                              # run the Workers locally
```

To deploy your own copy, create the resources listed in [the plan, section 2](docs/IMPLEMENTATION_PLAN.md#2-cloudflare-resources). Then put their IDs into each app's `wrangler.jsonc`, set secrets with `wrangler secret put`, and run `pnpm deploy`.

## Data and licences

**This repository contains code, not data.** The data is pulled at run time from public sources, and each source keeps its own licence. See [DATA_LICENSES.md](DATA_LICENSES.md).

Eight sources ship switched off or link-only until their owners give written permission. If you run your own copy, you are responsible for following each source's terms.

## Contributing

Adding a source is the most useful contribution. It takes a registry entry, a parser, a recorded fixture and a test; see [CONTRIBUTING.md](CONTRIBUTING.md). Please read the [Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Licence

Code: [Apache License 2.0](LICENSE). The Motiontic name and logo are not covered by this licence (see [NOTICE](NOTICE)).

## Before this repo goes public (maintainers)

- [ ] Fill in placeholders: `<ops-contact>`, `<domain>`, and the `<fill-after-create>` KV namespace ID. D1, R2 and Queues are found by name.
- [ ] Turn on GitHub private vulnerability reporting, secret scanning, Dependabot alerts and CodeQL.
- [ ] Pin GitHub Actions to commit SHAs.
- [ ] Run `pnpm install` and commit the lockfile, then `pnpm up --latest` once to confirm dependency versions.
- [ ] Confirm the "verify" items in the plan's section 18.
