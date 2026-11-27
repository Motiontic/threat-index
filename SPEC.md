# tasks-polish: richer deep-query rows, and tighter retry, charge and cancel rules for MCP Tasks

## Why

The Tasks change (#62) works and is safe, but a review after it merged found a few gaps.

- `mti_deep_query` rows for `package-advisories` don't say which versions are affected or fixed. That's the
  main point of the template.
- A few retry and error paths can charge a user's daily package quota again, or throw away chunks that were
  already charged.
- The Dockerfile check for DuckDB extensions accepts a build that would fail every query.

## Current state (on main after #62)

| Area | Today |
| ---- | ----- |
| `apps/mcp/src/tools/deep-format.ts` | Flattens each job row `{ source, jobId, record }` with a per-template field list. `package-advisories` has no `affected`. `cve-history` signal rows have no `ref` or `evidenceDate`. Summaries are cut at `CAPS.title` (200); `CAPS.summary` (600) exists. `cvssVersion` is dropped |
| `apps/mcp/src/tasks/mcp-task.ts` | Retries a chunk up to 3 times. The 2-try limit applies only when the failing try is itself a timeout. A 200 whose body can't be read counts as a plain failure and is retried. 401, a non-`blocked` 403, 400, 501 and a missing identity go to `toolError`, which drops finished chunks. The dedupe key uses the raw name. New table columns rely on `CREATE TABLE IF NOT EXISTS`. A cancel during the start POST leaves the E2B job running |
| `apps/mcp/src/tools/mti_deep_query.ts` | Schema has `required: []`. The pipeline refuses a start without `template` |
| `e2b/e2b.Dockerfile` | Checks that `json` and `parquet` appear in `duckdb_extensions()`, but accepts `loaded=false` |

## What to build

1. **Deep-query rows** (`deep-format.ts`):
   - `package-advisories`: add `affected`, a list of `{ introduced, fixed, lastAffected }` per range for the
     queried package. Values are version strings matching `^[A-Za-z0-9.+~:_-]{1,64}$`; anything else is
     dropped. At most 20 ranges.
   - `cve-history`: keep `ref` (an ID or URL, through `sourceLink` if it is a URL, else dropped) and
     `evidence_date` for signal rows, so several exploit rows for one CVE can be told apart.
   - Use `CAPS.summary` for summary fields. Keep `cvss_version` where the record has one.
   - Tests use the job's real row shapes for every template (from the job's own fixtures), and check the new
     fields.
2. **Retries never re-charge needlessly** (`mcp-task.ts`):
   - Keep a per-chunk `timedOut` flag in progress. Once any try of a chunk has timed out, at most one more try
     is allowed, whatever the later failure is.
   - Never retry after a 200, whatever goes wrong reading the body: the chunk's packages are listed as not
     checked (`answer_unreadable`), and the task carries on.
3. **Terminal errors keep finished work.** 401, a non-`blocked` 403, 400, 501 and a missing identity end through
   `endCheck`, with the merged partial result, `truncated: true` and a note, like the other terminal errors.
   Never drop charged chunks.
4. **Dedupe on the normalised key.** Build the dedupe key with the same normalised identity the formatter uses
   (`canonicalEcosystem` + `normaliseName` + version, or the parsed purl). So PyPI `Foo_Bar` and `foo-bar` merge.
5. **Cancel during start.** If `tasks/cancel` arrives while the deep-query start POST is in flight, the task is
   marked cancelled at once. When the POST returns 202 and the conditional update finds the task no longer
   `working`, send `DELETE /v1/deep-query/:id` straight away (and retry by alarm as for any cancel).
6. **Guarded schema upgrades.** On object start-up, add any missing column to existing tables with a guarded
   `ALTER TABLE` (check `PRAGMA table_info` first), so an object created by an earlier build keeps working.
   Add a schema version number in a `meta` table.
7. **Schema tells clients what's needed.** `mti_deep_query`'s input schema is `anyOf` [`{ required:
   ['template'] }`, `{ required: ['cursor'] }`] at the top level, if the description linter and the SDK accept
   it. If a known client rejects top-level `anyOf`, keep `required: []` and say so in PROOF.md.
8. **Dockerfile gate.** Require `json` and `parquet` to be loaded without a download: `install_mode =
   'STATICALLY_LINKED'` (or `loaded = true` on a fresh database with autoload off). Fail the build otherwise.

## Tests

- Each item above has a test. Deep-query tests use the job's real row shapes for all five templates.
- Retry tests:
  - timeout, then 5xx, then no third try;
  - a 200 with a broken body is not retried;
  - a 401 mid-task returns the partial result.
- Dedupe: `Foo_Bar` and `foo-bar` (PyPI) count once.
- Cancel during start: the job's DELETE is sent once the start returns.
- Schema upgrade: an object holding old-shape tables gets the new columns and runs a long check.

## Not in scope

- New tools, new templates, Tasks notifications.

## Acceptance criteria

1. `pnpm build` and the Workers tests pass; the lockfile is unchanged.
2. `package-advisories` rows say which versions are affected and fixed.
3. No path retries after a 200, or allows more than one try after a timeout. Terminal errors keep charged
   chunks.
4. A cancel during start stops the E2B job.
5. Old task objects upgrade in place.
