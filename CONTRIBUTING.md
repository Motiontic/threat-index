# Contributing to Threat Index

Thanks for helping. This guide covers setting up, the rules every change must follow, and how to add a source.

## Setting up

```bash
pnpm install
pnpm lint && pnpm typecheck && pnpm test
```

Node 22 and pnpm 10 are required. Unit tests run with plain Vitest. From M1, Worker integration tests use `@cloudflare/vitest-plugin` against local D1, R2 and Queues. Either way, you don't need a Cloudflare account to contribute.

## Ground rules

1. **No data in the repo.** Fixtures are small, trimmed samples of public responses, used only for tests. Each fixture folder has a `SOURCE.md` saying where it came from and under what licence.
2. **Respect source licences.** A new source must state its licence status in the registry: `on`, `ask`, `wait` or `link`. If the terms forbid commercial use or require written permission, the source ships as `wait` (off).
3. **Metadata only for exploits.** Never fetch, store or link to downloadable exploit code. Store the ID, date, URL and CVE only.
4. **Be polite to sources.** Use the shared `User-Agent`, honour `Retry-After`, use conditional requests, and stay within each source's published rate limits.
5. **Stay inside the free-plan budgets.** One queue message handles at most 40 records. Anything over about 1 MB goes to an E2B job. Count every D1 write with the budget meter.
6. **Every page credits its sources.** Don't remove or hide credit lines.

## Adding a source

1. **Source file:** add `packages/sources/src/sources/<id>.ts` with id, name, pattern, cadence, licence status and credit line, and list it in `packages/sources/src/registry.ts`.
2. **Pattern:** reuse one of the seven patterns in `packages/patterns`. Only add a new pattern if none fits, and explain why in the PR.
3. **Parser:** add `packages/parsers/src/<format>.ts`, or reuse an existing one. Return typed records and list any unknown fields.
4. **Fixture:** save one small, real response in `fixtures/<source-id>/`, with a `SOURCE.md`.
5. **Tests:** cover the parser on the fixture, and the "nothing changed" path of the pattern.
6. **Docs:** add the source to `DATA_LICENSES.md`.

## Pull requests

- Keep PRs small and focused; one source per PR is ideal.
- Fill in the PR template: what changed, how it was tested, licence notes.
- CI must be green: Biome, TypeScript, Vitest.
- Big design changes need an ADR in `docs/decisions/`.

## Commit messages

Use short, imperative subjects (`Add JVN feed parser`), and explain _why_ in the body when it isn't obvious.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
