# budget-paid: write budget sized for Workers Paid

## Why

The loader's first-load cap (`FIRST_LOAD_DAILY_CAP = 90,000` in `packages/core/src/budget.ts`) and
`D1_DAILY_WRITE_LIMIT = 100,000` are free-plan numbers. The account is on Workers Paid, where D1 includes 50
million rows written a month. With the old cap a full first load of the CVE List takes many days. Steady updates
are never capped and stay that way.

## What to build

1. Set `D1_DAILY_WRITE_LIMIT` to 1,600,000 (about 50M a month spread over a month) and `FIRST_LOAD_DAILY_CAP` to
   1,000,000. Update the comments to say they are Workers Paid numbers and why.
2. Update every test, doc and watchdog threshold that hard-codes 90,000, 100,000 or values derived from them
   (for example the loader tests that expect `90015`, the watchdog's "budget above 80%" check, docs in
   `docs/IMPLEMENTATION_PLAN.md` that state the cap). Grep for them all.
3. Keep `EMAIL_DAILY_CAP` unchanged.

## Not in scope

Anything else.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. `grep -rn '90_000\|90000\|100_000' packages apps docs` shows no stale free-plan budget numbers (list any that
   remain on purpose and why).
