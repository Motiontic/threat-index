# contracts: one file per feature, a Workers test harness, typed databases

## Why

Most features after this one are built on separate branches at the same time. Two branches that edit the
same file conflict, so they can't run side by side. Today almost every feature would touch the same few
files: every API route sits in `apps/api/src/index.ts`, the collector is one file, every package exports
through a barrel `src/index.ts`, and all 55 sources live in one array in `packages/sources/src/registry.ts`.

This change splits those files so that later work only **adds a new file** or **fills in a stub it owns**.
It also adds the test harness and the typed database access that every later feature needs.

It moves code. It adds no product behaviour.

## Current state (checked on main)

| Area | Today |
| ---- | ----- |
| `apps/api/src/index.ts` (158 lines) | Health, Clerk webhook (Svix verify + `svix-id` dedupe), `clerkMiddleware`, `requireUser`, `GET /v1/entries/:id` (preview vs full), `/v1/me/watch` routes, `deleteUserData`, helpers `resolveKey`, `credits`, `PREVIEW_FIELDS`, `PREFIX_SOURCE`, all inline |
| `apps/collector/src/index.ts` (64 lines) | `scheduled()` with `CADENCE_BY_CRON` and `dueSources()`, `queue()` with TODOs |
| `apps/loader`, `apps/notify` | One `index.ts` each |
| `packages/*/package.json` | `"main": "src/index.ts"`; `src/index.ts` is `export *` from each module |
| `packages/sources/src/registry.ts` | `SourceConfig`, the `src()` helper and all 55 sources in one array |
| `packages/patterns/src/index.ts` | Pattern types only; no pattern files |
| `packages/parsers/src` | `kev.ts` + test; barrel |
| `packages/db` | Hand-written SQL migrations `migrations/<db>/0001_init.sql` for six databases, `upsertNewerSql()`, `drizzle-orm` installed but no schema |
| `e2b/jobs/src/run.ts` | One file, a `JobKind` union of 7 jobs, no per-job code |
| Tests | Root `vitest.config.ts`, Node only. CI runs `pnpm lint`, `pnpm typecheck`, `pnpm test` |

The `0001_init.sql` migrations are already applied to the staging databases. **Do not edit any file under
`packages/db/migrations/`.**

## What to build

### 1. Subpath imports instead of barrels

- Every package under `packages/` gets `"exports": { "./*": "./src/*.ts" }` (plus `types` if `tsc` needs
  it). Adding a module must not require touching `package.json` or any other shared file.
- Delete each package's `src/index.ts` barrel. Rewrite every import in `apps/`, `packages/` and `e2b/` to a
  subpath, for example `@ti/core/ids`, `@ti/core/licence`, `@ti/sources/registry`.
- Biome or a test must fail if anyone imports a bare `@ti/<pkg>` again.

### 2. One file per source

- Move each source into `packages/sources/src/sources/<id>.ts`, which default-exports its `SourceConfig`.
  Keep the ids, names, patterns, cadences, licence statuses and credits exactly as they are today.
- `registry.ts` keeps the types, the `src()` helper, `SOURCES` and `SOURCE_BY_ID`, and imports all 55
  files once. After this change, nobody edits `registry.ts` to work on one source.
- Add optional fields to `SourceConfig` that later work fills per source: `urls?: string[]`,
  `parser?: string`, `rateLimit?: { perMinute: number }`. Add no values yet.
- The existing registry test still passes, and a new test checks that there are 55 unique ids and that each
  file's id matches its file name.

### 3. One file per pattern, parser and job

- `packages/patterns/src/<name>.ts` for the seven patterns (`git`, `changelist`, `since`, `fingerprint`,
  `feed`, `page`, `heavy`). Each exports `check()` and `fetch()` with the types in today's `index.ts`
  (moved to `packages/patterns/src/types.ts`). Their bodies throw a `NotImplementedError` from
  `@ti/core/errors`.
- `packages/parsers/src/<format>.ts` stubs for `cve-json5`, `osv`, `csaf`, `nvd`, `epss`, `stix`, `feed`
  (RSS/Atom) and `csv`, next to the real `kev.ts`. Each exports `parse(input) → ParsedRecord[]`; the stubs
  throw `NotImplementedError`. Keep `kev.ts` and its test unchanged apart from imports.
- A source names its parser through `SourceConfig.parser`. How the collector turns that name into a parser
  must not need a shared map that every parser change edits. Pick a design, explain it in the PR, and
  apply it to `cisa-kev` → `kev`.
- An unknown parser name fails with a clear `unknown parser: <name>` error. Any other failure while a parser
  module loads (a syntax error, a failing import, an exception at load time) is rethrown with its original
  error as the cause, not reported as an unknown parser.
- `e2b/jobs/src/jobs/<kind>.ts` for each of the 7 job kinds. Each exports `run(job, ctx)`; stubs throw
  `NotImplementedError`. `run.ts` dispatches by `kind` and exits non-zero for an unknown kind.

### 4. API routes, one module each

- `apps/api/src/index.ts` only builds the app: shared middleware, then mounting each route module. It has no
  handler bodies.
- Shared code moves to `apps/api/src/lib/` (`env.ts` for `Bindings`, `auth.ts` for `requireUser`,
  `credits.ts`, `resolve-key.ts`, `preview.ts`).
- One file per route group in `apps/api/src/routes/`: `health`, `search`, `entries`, `index-letter`,
  `sources`, `me`, `watch`, `saved-searches`, `deep-query`, `webhooks-clerk`, `webhooks-resend`,
  `unsubscribe`, `internal-jobs`.
- Routes that exist today keep their exact behaviour: health 200; Clerk webhook verifies, dedupes and
  upserts/deletes as now; `/v1/entries/:id` returns preview vs full; the watch routes need a user.
- New route modules register their paths and return `501 {"error":"not_implemented"}`. They keep the
  auth rules from the plan's route table: public, signed in, Svix-signed, signed token or HMAC. A stub that
  needs a user still returns 401 without one, and a webhook stub still rejects a bad signature, so auth is
  in place before any feature lands.
- Webhook routes stay outside `clerkMiddleware()`.
- `/v1/health` stays outside `clerkMiddleware()` too, as it is on main today: mount it before the middleware,
  so the health check answers 200 even when Clerk is misconfigured. Add a Workers test for that.

### 5. Collector, loader and notify modules

- Collector: `index.ts` only wires `scheduled` and `queue` to `planner.ts` (`CADENCE_BY_CRON`,
  `dueSources`), `step.ts` (one queue message), `watchdog.ts` (stub) and `backoff.ts`. Same cron
  behaviour as today. Nothing calls `watchdog.ts` yet; comments must say it is an unwired stub.
- Loader and notify: `index.ts` wires to a `consume.ts` holding today's logic. No behaviour change.

### 6. Typed databases

- `packages/db/src/schema/<db>.ts` for `control`, `vulns`, `advisories`, `signals`, `world` and `users`:
  Drizzle table definitions that match each `0001_init.sql` exactly (names, columns, types, primary keys,
  `WITHOUT ROWID` noted in a comment).
- The SQL migrations stay the source of truth. Don't add `drizzle-kit` migration generation.
- A Workers test applies the migrations to local D1 and checks that every Drizzle table's columns equal
  `PRAGMA table_info` for that table.
- Move `upsertNewerSql` and `MAX_STATEMENTS_PER_INVOCATION` to `packages/db/src/sql.ts`. Its comment
  says the free plan allows 50 queries per invocation; the account is now on Workers Paid. Keep the value
  40 and fix the comment to state the reason (batch size and CPU time per step), not the free plan.

### 7. Test harness

- Two kinds of test:
  - **`pnpm test`**: Node-only Vitest. This is part of `pnpm build` and must stay light enough for a
    laptop (no `workerd`).
  - **`pnpm test:workers`**: `@cloudflare/vitest-plugin`, one project per Worker app that has bindings,
    using that app's `wrangler.jsonc` and its `env.staging` section with local D1, R2, KV and Queues.
    Migrations are applied in setup with `applyD1Migrations`. `@cloudflare/vitest-pool-workers` is the
    deprecated old name of this package; don't use it. Keep `vitest` at `^5.1.0`, as on main.
  - Workers tests run at the apps' own compatibility date. If the plugin's bundled `workerd` can't, use the
    newest date it accepts and state the exact versions and dates in the PR.
- The wrangler configs contain `${VAR}` placeholders (KV ids). Use `scripts/wrangler-config.mjs` or a
  test-only config to resolve them with dummy values. Don't commit real ids.
- `test/fixtures.ts`: `fixture(source, file)` returns the text of `fixtures/<source>/<file>`, and works
  in both kinds of test.
- First Workers tests, which prove the harness:
  - api: health 200; unsigned Clerk webhook 400; `/v1/me/watch` without a session 401; an
    `/v1/entries/:id` row inserted into local D1 returns preview fields to a visitor.
  - collector: `scheduled()` with `0 */3 * * *` sends one job per due source to the local queue, and no
    source whose licence status is `wait` (looked up in `SOURCE_BY_ID`) is sent. `link` sources are still
    collected (they keep only ID, title, date and link), as `canIngest()` decides today.
  - db: the Drizzle-matches-SQL test above.
- CI (`.github/workflows/ci.yml`) runs `pnpm test:workers` after `pnpm test`. This is a sensitive path, so
  the loop stops for review anyway.

### 8. Docs and review settings

- Update `docs/adding-a-source.md` for the new layout (source file, parser file, fixture, tests).
- Check that `REVIEW.md` and `review.sensitivePaths` in `loops.json` still match the moved files: the
  Clerk and Resend webhook routes, `lib/auth.ts`, `internal-jobs.ts`, `packages/core/src/licence.ts` and
  `packages/sources/src/registry.ts`. Fix any glob that no longer matches.

## Not in scope

- Any feature logic: patterns, parsers other than KEV, jobs, search, alerts. Stubs only.
- New migrations, or any change to `packages/db/migrations/`.
- Wrangler binding changes, deploy scripts, `.github/workflows/deploy.yml`.
- New runtime dependencies. The only new dev dependency is `@cloudflare/vitest-plugin` (plus its peers).
  No other dependency changes version. This branch owns `pnpm-lock.yaml`.

## Acceptance criteria

1. `pnpm build` passes and starts no `workerd` process.
2. `pnpm test:workers` passes in the loop sandbox, with the tests listed in section 7.
3. No `src/index.ts` remains under `packages/`. `rg "from '@ti/[a-z-]+'" apps packages e2b` finds
   nothing, and the lint rule or test from section 1 fails on such an import.
4. `apps/api/src/index.ts` contains no handler bodies, and each route group from section 4 has its own file.
5. Adding a source, a parser, a pattern, a job or an API route needs only new files or edits inside that
   feature's own file. Explain this in the PR with the exact files a new parser for one source would touch.
6. `git diff --stat main -- packages/db/migrations` is empty.
7. Proof saved: the `pnpm build` and `pnpm test:workers` output, plus one `wrangler dev` run of the api on
   port 8700 inside the sandbox with `curl` results for health, an unsigned webhook and `/v1/me/watch`.
8. `@cloudflare/vitest-pool-workers` appears in no `package.json` and not in `pnpm-lock.yaml`, and root
   `vitest` is still `^5.1.0`.

## Changes from the first build of this branch

This branch already implements most of the spec above. A review of the first build found these gaps. Fix
them on top of the existing commits; don't redo work that already matches the spec.

1. Replace `@cloudflare/vitest-pool-workers@0.23.0` with the current `@cloudflare/vitest-plugin`, move
   `vitest` back to `^5.1.0`, and drop the `WORKERD_MAX_COMPAT_DATE` override if the new plugin accepts the
   apps' compatibility date (section 7).
2. Mount `/v1/health` before `clerkMiddleware()` and test it (section 4).
3. `loadParser` maps only a missing parser module to `unknown parser`, and rethrows other load errors with
   the cause (section 3).
4. The collector test checks real licence statuses through `SOURCE_BY_ID`, not the made-up id
   `hhs-ocr-wait`: no `wait` source is sent (section 7).
5. The collector comment says `watchdog.ts` is an unwired stub (section 5).

`PROOF.md` must describe the whole branch, not only these fixes, because it becomes the PR body. Re-run
every check in the acceptance criteria.
