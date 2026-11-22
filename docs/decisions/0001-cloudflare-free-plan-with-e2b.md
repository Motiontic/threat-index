# 0001. Cloudflare free plan for the always-on system, E2B for heavy work

- Status: accepted
- Date: 2026-11-22

## Context

We need a pipeline that checks 55 sources every 3 hours, keeps a full history and serves an API, with no cash spend. Cloudflare's free plan gives Workers, D1, R2, Queues, KV and cron at $0. However, it allows only **10 ms of CPU per invocation** and **100,000 D1 row writes a day**. We have existing E2B credits.

## Decision

- **Cloudflare runs everything always-on:** scheduling, change detection, small updates, storage, the API and the web app.
- **E2B sandboxes run anything heavy:**
  - files over about 1 MB;
  - the first load;
  - the nightly fold of receipts into Parquet;
  - search-index builds;
  - deep-history queries with DuckDB.
- **D1 holds only the hot set.** The full history lives as Parquet in R2. Writing one file is one R2 operation, not millions of D1 writes.
- **GitHub Actions is not used for the pipeline.** Its terms limit Actions to building, testing and deploying the repo's own software.

## Consequences

- The first load takes about 2 weeks for the hot set, but the full history is queryable on day 1.
- Steady state is about 20,000 D1 writes a day, with about 70,000 to spare.
- If E2B credits end, the same jobs run on a laptop (`pnpm job <name>`), and the $5 Workers plan is the escape hatch.
