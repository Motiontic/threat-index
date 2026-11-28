# changelist-catch-up: change-list sources stop stalling on a burst

## Why

Three change-list sources have loaded nothing since 24 Nov 2026, on staging and production:

| Source | Last good load | Every 3-hour update since | Changes waiting |
| --- | --- | --- | --- |
| `osv` (global `modified_id.csv`) | 24 Nov 06:27 UTC | `big-file` fails: `too many changes: 183403` | 183,497 |
| `ubuntu` (OSV `Ubuntu/modified_id.csv`) | 24 Nov 06:53 UTC | `too many changes: 72336` | 72,336 |
| `red-hat` (CSAF VEX `changes.csv`) | 24 Nov 06:21 UTC | `too many changes: 30566` | 30,566 |

Upstream had real bursts: Ubuntu re-published about 70,500 records on 24 Nov, Red Hat changed 17,700 files on
26 Nov, and the global OSV list carried 23,000–41,000 changes a day from 24 to 27 Nov.

Cause: `applyCap` (`e2b/jobs/src/lib/changelist.ts`) throws in `update` mode when the window `(from, to]` holds
more than `MAX_LIST_DOCS` (10,000) lines. The cursor moves only when a job completes
(`apps/api/src/routes/internal-jobs.ts`), so after a burst the backlog only grows and the source never recovers.

Most of the `osv` backlog is also wasted work. The `osv` parser keeps only the language ecosystems in
`LANGUAGE_ECOSYSTEMS` (`packages/parsers/src/osv.ts`), but the job fetches every listed document first. Of the
183,497 waiting `osv` lines, only **2,007** are in kept ecosystems; the rest are Ubuntu (72,336), Chainguard
(56,989), Red Hat (15,832), Azure Linux, Wolfi, Android and so on. Each list line's ref starts with the
ecosystem's directory (`npm/GHSA-…`, `Ubuntu/UBUNTU-CVE-…`, `GitHub Actions/GHSA-…`).

## What to build

1. **An update works through a large backlog in steps instead of failing.**
   - In `update` mode, when the window holds more than `MAX_LIST_DOCS` lines, keep the **oldest**
     `MAX_LIST_DOCS` lines (the ones right after `from`), process them as usual, and record the last kept line
     as `reached = [time, ref]`. `first-load` mode is unchanged: it keeps the newest `MAX_LIST_DOCS`.
   - The job writes `reached` into the inbox manifest as an optional field
     `cursor: { kind: 'timestamp', value: JSON.stringify([time, ref]) }`, only when it stopped short.
     When everything in the window was processed, the manifest has no `cursor` and today's behaviour holds
     (the API moves the cursor to the request's target, with its etag).
   - Log `change list read` with `lines`, `older`, `filtered` (item 2), `partial` and, when partial,
     `reached`.
2. **The global `osv` list is filtered to the ecosystems the parser keeps, before the cap and before any fetch.**
   - Add an optional `refPrefixes?: string[]` to the `changelist` pull config (`packages/sources/src/pull.ts`).
     A line is kept when its ref's text before the first `/` is in the list. Lines it drops are counted as
     `filtered`, not `unreadable`.
   - Set it on `osv` (`packages/sources/src/sources/osv.ts`) to exactly the `LANGUAGE_ECOSYSTEMS` names. Add a
     test that the two sets are equal, so they can't drift. The test must live where both packages may be
     imported without adding a new runtime dependency between them.
   - Apply the filter in **both** places that read the list, with one shared helper:
     - the job's `readChangeList` (both modes);
     - the collector pattern's `scan` (`packages/patterns/src/changelist.ts`). Here `newest` still considers
       **every** readable line, so the target cursor moves past dropped lines; only `fresh` is filtered.
   - When a scan is complete, nothing kept is fresh, and `newest` is after the stored cursor, the run moves the
     cursor to `newest` (with the validator) and fetches nothing. Today it returns `unchanged`, which would leave
     the cursor behind the dropped lines, and every later scan would have to read further back.
   - `ubuntu`, `debian` and `red-hat` get no `refPrefixes` (they keep everything).
3. **ti-api accepts a job's partial cursor, within limits.** In the job-complete handler, when the manifest has a
   `cursor`:
   - It is used only for a job that has a `source_id` and whose stored request has a `from` cursor and a target
     `cursor`, both `timestamp` pairs.
   - Its `kind` must be `timestamp`; its `value` must parse as a `[time, ref]` pair of strings, at most
     512 characters in all, whose time parses as a date.
   - It must be **strictly after** `from` and **not after** the target, ordered by (time in ms, then ref), the
     same order the job and the pattern use. Put that comparison in one pure shared function (in `@ti/core`) and
     use it from the job, the pattern and the API.
   - Store it with **no etag**, so the next run's `check` doesn't answer `unchanged` from the list's validator.
   - Any check failing fails the job with `invalid_manifest: bad cursor`, and the stored cursor stays where it
     was. The cursor still moves only after every load message is sent, as today.
   - `parseManifest` (`apps/api/src/lib/e2b.ts`) validates the optional field's shape; the bounds check needs
     the stored request, so it runs in the handler.
   - This is security-relevant: sandbox output now picks a cursor value in `ti_control`. The bounds mean a
     sandbox can only move a cursor forward, never past what the collector planned, so the worst it can do is
     slow a source down, which a failing job already does. Flag it for human review.

## Tests

- `e2b/jobs`:
  - `applyCap`: an update over the cap keeps the oldest 10,000 and returns `reached` = the 10,000th line; an
    update at or under the cap returns everything and no `reached`; first-load still keeps the newest 10,000.
  - Lines with equal times in ms: the cut and `reached` follow the (ms, ref) order, and the next window starting
    at `reached` neither repeats nor skips a line.
  - `readChangeList` with `refPrefixes`: `npm/…`, `PyPI/…`, `GitHub Actions/…` kept; `Ubuntu/…`,
    `Chainguard/…`, a ref with no `/` dropped and counted as `filtered`.
  - The big-file job writes the manifest `cursor` only when partial.
  - The `refPrefixes` ↔ `LANGUAGE_ECOSYSTEMS` equality test.
- `packages/patterns`: `scan` with `refPrefixes` counts only kept lines as fresh, while `newest` covers all lines;
  a complete scan with only dropped lines moves the cursor to `newest` and fetches nothing.
- `apps/api` (job-complete handler, Workers tests):
  - a valid partial cursor is stored with no etag;
  - a cursor equal to `from`, before `from`, after the target, of another kind, unparsable, or over 512
    characters fails the job with `invalid_manifest: bad cursor` and leaves the stored cursor unchanged;
  - no manifest cursor: the target and its etag are stored, as today;
  - a manifest cursor on a job with no `source_id` fails the job.
- `pnpm build` clean, and the Workers tests pass.

## After merge (operator, not the loop)

No manual recovery is needed. Each 3-hour collector run hands off a `big-file` job, which now completes and
moves the cursor up to 10,000 changes forward. Expected: `osv` catches up in one run (about 2,000 kept
lines), `red-hat` in about 4 runs, and `ubuntu` in about 8 runs (one day). Catch-up writes are steady writes, which the budget meter counts but never
blocks. Catch-up changes follow the existing quiet rules and the notify caps.

## Not in scope

- The affected-backfill re-sending unchanged records when a source is reopened.
- Full-history loads for OSV, Debian or Ubuntu, and a per-ecosystem OSV fan-out.
- Changing `MAX_LIST_DOCS`, the 3-hour schedule, or chaining a follow-on job straight after a partial one.

## How to revert

`git revert` the merge and redeploy. Cursors moved by partial runs are valid points in each list, so the old code
simply carries on from them (and stalls again on the next large burst).
