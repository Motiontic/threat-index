# ops-script-fixes: three operator scripts that broke or misled on production

## Why

Three scripts an operator runs by hand failed or misled during the 28 Nov production deploy and the backfill:

| Script | What happened | Cause |
| --- | --- | --- |
| `scripts/quiet-old-changes.mjs --env production` | Stopped with `D1 DB is overloaded. Too many resources consumed within a 10 second window. [code: 7429]` on `ti_advisories` | The `fix` read groups the whole `advisories` table (512,431 rows on production) on every page, with keyset `(source, vuln_key) > (…)` and no index on `(source, vuln_key)`. The `exploit` read does the same over `signals`. Staging's tables are small enough that it worked there. |
| `scripts/smoke-staging.mjs` against production | `4 of 29 checks failed`, exit 1, on every production run | The 4 MCP rows expect MCP switched on (405, 200, 401). Production runs with `MCP_ENABLED = "0"`, so they answer 404, which is correct for production until launch. |
| `e2b/jobs/src/start-job.ts --kind affected-backfill` | Refused: `--kind must be one of first-load, epss-diff, big-file, nightly-fold, search-index, echo` | `KINDS` was not updated when the `affected-backfill` job was added; ti-api accepts it (`ENABLED_JOB_KINDS` in `apps/api/src/lib/e2b.ts`). Operators had to call `startJob` through `node -e`. |

The production backlog was finished with a one-off runner that uses the same planner (`scripts/lib/quiet-plan.mjs`)
but reads dates only for the keys it needs. On 28 Nov it read 87,728 rows, marked 71,213 `old` and 3,488
`first_load`, and left 13,027 alerting, with no overload. Item 1 moves that approach into the repo script.

## What to build

1. **`quiet-old-changes.mjs` reads dates by key.**
   - Read `changes` first, as today.
   - Then read the exploit and fix dates **only for the keys the changes need**, in batches of at most 800
     quoted keys per query:
     - exploit: the distinct `entity_key` of `public_exploit` rows.
       `SELECT vuln_key, MIN(first_seen) AS d FROM signals WHERE vuln_key IN (…) AND kind = 'public_exploit' GROUP BY vuln_key`.
       This uses `signals`' primary key `(vuln_key, kind, source, ref)`.
     - fix: the distinct `entity_key` of `fix_released` rows.
       `SELECT source, vuln_key, COALESCE(MIN(published), MIN(modified)) AS d FROM advisories WHERE vuln_key IN (…) GROUP BY source, vuln_key`.
       This uses `advisories_by_vuln`.
   - Map keys stay as they are today (`vuln_key`; `source \u0000 vuln_key`). `planQuiet` only looks up those
     keys, so the plan is identical to a whole-table read.
   - Put the pure parts in `scripts/lib/quiet-plan.mjs`:
     - `neededKeys(changes)` returns `{ exploit: Set, fix: Set }`;
     - `keyBatches(keys, size = 800)` returns sorted arrays;
     - `exploitDatesSql(batch)` and `fixDatesSql(batch)` build the SQL strings, quoting with the existing `lit`
       rule (single quotes doubled).
   - **Retry on overload.** When a wrangler call fails and its output contains `7429` or `overloaded`, wait
     5 s × the attempt number and retry, at most 5 retries. Any other error stops the script, as today. A retry
     never repeats a write that succeeded: writes are the existing `--file` chunks, each guarded by
     `AND quiet IS NULL`, so re-running a chunk is harmless anyway.
   - Print progress to stderr every 10 batches. Keep the dry-run output format unchanged.
2. **`smoke-staging.mjs --mcp off`.** A new optional flag, `--mcp on|off`. The default is `on`, so today's
   behaviour is unchanged.
   - With `off`:
     - `GET /mcp`, `GET /.well-known/oauth-protected-resource/mcp`, `GET /mcp/server-card` and the no-token
       `POST /mcp` must each answer **404** and set no cookie;
     - the `If-None-Match` row is skipped;
     - every other row is unchanged.
   - Row labels say which mode they checked (for example `web /mcp (MCP off)`).
   - Update the usage line and the header comment. Production runs use `--mcp off` until launch.
3. **`start-job --kind affected-backfill`.**
   - Add `affected-backfill` to `KINDS`.
   - Add a unit test that `KINDS` holds every kind in ti-api's `ENABLED_JOB_KINDS`, except `deep-query`. That
     kind is started by ti-api for a signed-in user, never by an operator, and the test names it as the one
     exception. The test reads `apps/api/src/lib/e2b.ts` as text and matches the array, so `e2b/jobs` does not
     import api code.
   - Update the usage text.

## Tests

- `scripts/quiet-plan.test.ts`:
  - `neededKeys` picks only `public_exploit` and `fix_released` entity keys, without duplicates;
  - `keyBatches` splits 1,801 keys into 800/800/201, sorted;
  - both SQL builders quote `a'b` as `'a''b'` and contain `IN (` and the right `GROUP BY`;
  - **equivalence:** on the existing fixture, a plan built from by-key maps equals the plan built from the full
    maps.
- A unit test for the retry wrapper with a fake runner:
  - two 7429 failures, then success: one result;
  - a non-overload error: thrown at once;
  - six 7429 failures: thrown after 5 retries.
  - Inject the sleep so the test doesn't wait.
- A smoke test with a fake `fetch` (the existing `runSmoke(fetchImpl, …)` seam):
  - `mcp: 'off'` with 404s passes, and with a 405 fails;
  - `mcp: 'on'` behaves as today.
- `e2b/jobs/src/start-job.test.ts`:
  - `parseArgs(['--api', 'https://x', '--kind', 'affected-backfill'])` is accepted;
  - the `ENABLED_JOB_KINDS` check described in item 3.
- `pnpm build` clean.

## Not in scope

- No change to the planner's rules (`planQuiet`, `firstLoadBoundaries`, `age.ts`), to the database or to any Worker.
- No new indexes. The reads above use indexes that exist on both environments today.
- Running anything against staging or production: the operator does that after merge.

## Acceptance criteria

- On a fixture, `quiet-old-changes.mjs` builds the same plan as before, and no query in it groups a whole table.
- An overloaded D1 call is retried, and other failures still stop the script.
- `node scripts/smoke-staging.mjs --web … --api … --mcp off` passes against an MCP-off deployment, and the
  default still checks MCP on.
- `start-job --kind affected-backfill` is accepted.
- `pnpm build` is clean, and review and security review have converged.
