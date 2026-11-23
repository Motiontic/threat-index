# Contributing to Threat Index

Thanks for helping. This guide covers setting up, the rules every change follows, and how pull requests are
reviewed. To add a source, see [docs/adding-a-source.md](docs/adding-a-source.md). For how the pieces fit
together, see [docs/architecture.md](docs/architecture.md).

## Setting up

You need Node 22 and pnpm 10. You do not need a Cloudflare account.

```bash
pnpm install --frozen-lockfile
pnpm build
```

## The laptop-light rule

`pnpm build` is the quick check: Biome (`pnpm lint`), `tsc` (`pnpm typecheck`) and the Node unit tests
(`pnpm test`). It starts no `workerd`, no dev server and no database, and makes no network calls, so it stays
light enough to run on a laptop. Keep it that way.

Anything that needs the Workers runtime (local D1, R2, KV, queues) is a test named `*.workers.test.ts`.
`pnpm test` skips those; `pnpm test:workers` runs them, and CI runs both on every PR. Run `pnpm test:workers`
yourself if you change Worker code.

## Ground rules

1. **No data in the repo.** Fixtures are small, trimmed samples of public responses, used only for tests. Each
   fixture folder has a `SOURCE.md` saying where it came from and under what licence.
2. **Respect source licences.** A source's registry entry states its status: `on`, `ask`, `wait` or `link`. If
   the terms forbid commercial use or require written permission, the source ships as `wait` (off).
3. **Metadata only for exploits.** Never fetch, store or link to downloadable exploit code. Keep the ID, date,
   URL and CVE.
4. **Be polite to sources.** Use the shared `User-Agent`, honour `Retry-After`, use conditional requests, and
   stay within each source's published rate limits.
5. **Stay inside the free-plan budgets.** One queue message handles at most 40 records. Large files go to an
   E2B job. Count every D1 write with the budget meter.
6. **Every page credits its sources.** Don't remove or hide credit lines.

## Adding a source

Follow [docs/adding-a-source.md](docs/adding-a-source.md). In short: a source file, a parser if none fits, a
trimmed fixture with a `SOURCE.md`, and tests. One source per PR.

## How pull requests are reviewed

- CI must be green: lint, typecheck, `pnpm test` and `pnpm test:workers`.
- Fill in the PR template: what changed, how it was tested, licence notes.
- A maintainer reviews against [REVIEW.md](REVIEW.md), which lists what blocks a merge: licence gates,
  secrets, budgets, migrations and personal data.
- Changes to workflows (`.github/workflows`), `wrangler.jsonc`, migrations, and auth or webhook code get an
  extra maintainer look.
- Never edit a migration that may already be applied; add a new `NNNN_name.sql` in
  `packages/db/migrations/<db>/`.
- Keep PRs small; one source per PR.

## Licence rules for sources

Record what you found in the PR and in `fixtures/<id>/SOURCE.md`. You propose a status; maintainers decide,
and only they move a source between `wait` and `ask`. Never change another source's status in a source PR.

## Design changes

Big design changes need an ADR in [docs/decisions/](docs/decisions/), numbered after the last one.

## Commit messages

Use short, imperative subjects (`Add JVN feed parser`), and explain _why_ in the body when it isn't obvious.

## Conduct and security

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately, as described in
[SECURITY.md](SECURITY.md); don't open a public issue.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
