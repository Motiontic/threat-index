## gstack-loops (loop-engineering)

This workspace uses [gstack-loops](https://github.com/csakash/gstack-loops) on top of
[gstack](https://github.com/garrytan/gstack). Repos: threat-index.

**Every feature is a loop. Never edit `main` or the root checkouts directly** — parallel
sessions share these repos; an isolated worktree per loop is what stops them clobbering each
other. Start each feature with `gloop new <slug>`, then work inside `worktrees/<slug>/`.

The loop: `/gloop-spec` (commit `SPEC.md`) → `/gloop-build` (build → fresh-context review
and security review → `/qa`, with proof) → `/gloop-ship` (raise the PR). There's a
`/gloop-*` shortcut for every step, or just `/gloop <what you want>` to drive it
conversationally. For headless runs use `gloop run <slug> --mode <interactive|bypass|autonomous>`.

- Use `/browse` for all web browsing/QA — never `mcp__claude-in-chrome__*`.
- Definition of Done: behavior matches `SPEC.md`; `PROOF.md` (Testing / Risk / How to revert)
  is the PR body; `npm run build` clean per repo; review and security review converged, every
  important finding fixed or closed with a reason; each repo's `REVIEW.md` followed; sensitive
  paths flagged for a human reviewer (`gloop risk`); no `.env` committed; cross-repo PRs
  cross-linked.
- Landing several PRs at once: see [docs/PARALLEL_SHIPPING.md](docs/PARALLEL_SHIPPING.md)
  (shared-DB isolation via `hooks.preLoop`, merge order, rebase-before-ship).
- After a loop's PR merges: `gloop reap` (records the merge, re-checks recent merges for
  reverts). `gloop stats` shows how loops are doing.

## Threat Index: building and testing here

The plan is `docs/IMPLEMENTATION_PLAN.md`; how to add a source is `docs/adding-a-source.md`.

**Where code runs.** Build loops run in E2B sandboxes, one sandbox per loop, never on the laptop.
Check `TI_LOOP_SANDBOX`: it is `1` inside a loop sandbox and unset on a laptop.

- Run loops with `gloop run <slug> --mode <m> --no-servers`. gloop never starts dev servers in this
  repo; the `dev` command in `loops.json` refuses on purpose.
- **In a loop sandbox** (`TI_LOOP_SANDBOX=1`): you may run `wrangler dev`, Miniflare and the Workers
  test pool. Each loop has its own sandbox, so local D1, R2, KV and queues are private to it. Apply
  migrations with `wrangler d1 migrations apply <db> --local`. Use ports from 8700 up, one per app, and
  stop every server you start before your stage ends. The sandbox holds no Cloudflare or GitHub
  credentials: `pnpm preview`, deploys and `git push` fail there by design. Branches leave the sandbox
  as a git bundle and are pushed after review.
- **On a laptop**: never run `wrangler dev`, `pnpm dev`, Miniflare or any local server or database.
  To exercise running code, run `pnpm preview`. It uploads this branch's API as a preview version of
  the staging Worker and prints its URL (`https://<branch>-ti-api-staging.<subdomain>.workers.dev`).
  The preview uses the staging D1, R2, KV and queues and gets no cron or queue events. If the branch
  adds a migration, `pnpm preview --migrate` applies it to the staging databases once.
- The quick gate is `pnpm build` (Biome, `tsc`, pure unit tests); it must stay light enough for a
  laptop. Tests that need the Workers runtime run in loop sandboxes and CI, not in `pnpm build`.
- In a new worktree, run `pnpm install --frozen-lockfile` first. pnpm links from its shared store, so
  this is cheap.

**Environments.**

- Staging deploys automatically after CI passes on `main` (`.github/workflows/deploy.yml`). Its
  resources end in `_staging` or `-staging`.
- Production deploys from a `v*` tag or a manual run of the same workflow, and only after a reviewer
  approves the `production` environment. Never deploy production from a laptop or a loop.
- In each `wrangler.jsonc`, the top level is production and `env.staging` is staging. D1, R2 and Queues
  are found by name. Account-specific values are `${VAR}` placeholders that
  `scripts/wrangler-config.mjs` fills from the environment or the gitignored `.env`.

**Rules.**

- Never edit a migration that has been applied; staging applies them on every merge. Add a new
  `NNNN_name.sql` in `packages/db/migrations/<db>/`.
- Secrets live in Wrangler secrets, local `.dev.vars` or GitHub environment secrets, never in the repo.
- Accounts are single-user Clerk users. Never read `orgId`.
