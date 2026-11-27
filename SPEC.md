# alert-age-rule: old items stop triggering alerts, and a source's first load is quiet

## Why

A `changes` row (signals DB) is what notify matches against watches and saved searches, and what the home page
lists as "latest". The linker writes one when a stored state flips (`packages/linker/src/detect.ts`,
`packages/linker/src/changes.ts`). The row's only date is `at`, the time it was linked, not the date the event
happened at the source. So when a source loads for the first time, every old item looks like news. A user watching
OpenSSL would be mailed a 2014 exploit as if it came out today.

Staging on 27 Nov 2026 (rows written 23–27 Nov):

| Kind | Source | Rows | Event more than 14 days before the row was written |
| --- | --- | --- | --- |
| `public_exploit` | exploit-db | 37,225 | 37,223 |
| `public_exploit` | metasploit | 2,939 | 2,933 |
| `newly_exploited` | cisa-kev | 1,796 | 1,769 |
| `fix_released` | github-advisory-db | 15,535 | 15,240 |
| `fix_released` | msrc | 7,951 | 6,846 |
| `fix_released` | debian | 2,477 | 1,294 |
| `fix_released` | red-hat, ubuntu, osv | 742 | 628 |
| `breach_notice` | wa-ag, hhs-ocr, ca-ag | 1,868 | 1,827 |
| `breach_notice` | hibp | 890 | the stored notice has no notified or discovered date |
| `epss_band` | epss | 12,799 | current: the day's scores |
| `new_advisory`, `cvss_change` | several | 34 | already limited to 14 days, or current |

How the event date was measured: `public_exploit` = the earliest `first_seen` of the vulnerability's
`public_exploit` signals; `newly_exploited` = the KEV `dateAdded` (the row's `new`); `fix_released` = the earliest
`published` of that source's advisories for the vulnerability; `breach_notice` = `notified`, else `discovered`.

Production holds about 87,000 change rows of the same kinds.

The data itself is right: these exploits, fixes and notices exist, and package checks and entry pages should keep
showing them. Only the "this is new" signal is wrong.

## What to build

1. **Two columns on `changes`.** New signals migration (`packages/db/migrations/signals/0004_…sql`):
   - `event_at TEXT`: the date the event happened at the source (ISO day or timestamp). Null when the source gives
     none.
   - `quiet TEXT`: null means the row may alert. Otherwise, why it may not: `old`, `first_load` or `held`. Add a
     CHECK on these values if D1 accepts it in `ALTER TABLE ADD COLUMN`; otherwise check in code.
   - A partial index for the readers: `CREATE INDEX changes_alerts ON changes (at, id) WHERE quiet IS NULL`.

   Add both columns wherever the `changes` column list lives (linker `tables.ts`, the db schema and table info, the
   loader's inbox tables; `grep -rn "'changes'" apps packages e2b`). A quiet row is stored like any other and is
   never deleted for being quiet.

2. **Age rule, in the linker.** One pure module (for example `packages/linker/src/age.ts`) with
   `ALERT_WINDOW_DAYS = 14`. The linker sets `event_at` on each change row it writes:
   - `newly_exploited`: the KEV `dateAdded` (already the row's `new`).
   - `public_exploit`: the earliest `firstSeen` among this batch's `public_exploit` signals for the vulnerability.
     Record it on the draft next to `changeSource` in `applySignal`.
   - `fix_released`: the `published` of the advisory that set `fixSource`; if it has none, its `modified`.
   - `breach_notice`: `notified`, else `discovered`. Never `occurredFrom` or `occurredTo`: when a breach happened is
     not when it became public.
   - `new_advisory`: the advisory's `published`. Keep its existing 14-day rule, and make it use the same constant.
   - `cvss_change`: null. A score change is current.

   If `event_at`'s day is more than 14 days before `at`'s day, set `quiet = 'old'`. Exactly 14 days still alerts. A
   missing, unparseable or future date never makes a row quiet.

3. **A source's first load is quiet.**
   - **Bulk jobs.** In `e2b/jobs/src/jobs/first-load.ts`, mode `first-load` gives every change row
     `quiet = 'first_load'` (unless it is already `old`), next to where it already drops `new_advisory` rows. Mode
     `update` (`big-file`) gets only items 2 and 4.
   - **Collector steps** (`apps/collector/src/step.ts`). A source is on its first pass until it has a completed run
     other than the current one:
     - a `runs` row with status `unchanged`;
     - or a `runs` row with status `ok` whose `error` does not start with `step limit reached`;
     - or a `jobs` row with status `complete` and kind `first-load` or `big-file`.

     Read this in the existing step-2 batch, so it adds no round trip. While the source is on its first pass, every
     change row from the step gets `quiet = 'first_load'` (unless it is already `old`). Base the rule on `runs`
     and `jobs`, not on `cursors`: some sources never return a cursor and would otherwise stay on their first pass
     forever.

4. **Hold above 2,000 per run.** `MAX_ALERTS_PER_RUN = 2000` counts rows still `quiet IS NULL` after items 2
   and 3.
   - **Collector.** Add `runs.alerts INTEGER NOT NULL DEFAULT 0` in a new control migration. Read it with the run
     status in step 2, and add the step's alertable count in `commitCursor`'s run update (the same batch, so a
     redelivered step can't count twice). When a step would take the run past 2,000, the rows over the limit get
     `quiet = 'held'`. The run keeps its first 2,000.
   - **`big-file` jobs.** The same limit per job.
   - Log `{"event":"changes.held","sourceId":…,"runId":…,"held":N}` once per step that holds rows (in jobs, with
     `jobId` instead of `runId`).
   - The epss-diff job keeps its own `MAX_CHANGES` and is outside this rule.
   - Held rows are released by hand with an `UPDATE changes SET quiet = NULL WHERE quiet = 'held' AND source = ? AND
     at BETWEEN ? AND ?`. Put that in PROOF.md's How to revert, and next to the existing operations notes in
     `docs/`.

5. **Readers.**
   - **notify** (`apps/notify/src/collect.ts`): the forward and late reads add `quiet IS NULL` and use the partial
     index. The paging, the cursor format, the page and time budgets and the late-window rules stay as they are.
   - **Home** (`apps/api/src/lib/home.ts`, `changeItems`): `WHERE quiet IS NULL`.
   - **Entry history** (`apps/api/src/routes/entries.ts`): unchanged. It shows quiet rows too, because the history
     is true.
   - **Logs.** When any count is non-zero, the collector logs
     `{"event":"changes.quiet","sourceId":…,"runId":…,"step":…,"old":N,"firstLoad":N,"held":N}` per step, and jobs
     log the same counts. Counts only: no entity keys, user IDs or email addresses.

6. **Backlog script.** Add `scripts/quiet-old-changes.mjs`:
   - `node scripts/quiet-old-changes.mjs --env staging|production` is a dry run: it prints counts by kind, source
     and reason. `--apply` writes.
   - It touches only rows with `quiet IS NULL`, and it sets only `event_at` and `quiet`. It uses the same functions
     as items 2 and 3 (import them, so there is one rule). It never deletes, and a second run changes nothing.
   - Where it gets the dates:
     - `public_exploit`: signals, in the same DB;
     - `newly_exploited`: `new`;
     - `fix_released`: the advisories DB, the earliest `published` of that source's advisories for the
       vulnerability (`modified` if none has a `published`);
     - `breach_notice`: the world DB's `breach_notices`, keyed by the `source:notice_id` in `new`.
   - First pass, from the control DB's `runs` and `jobs`:
     - rows written at or before the end of the source's first completed run or job are `first_load`;
     - if the source has runs but none completed, all its rows are;
     - if the source has no runs (for example `cisa-vulnrichment`, which is read from CVE List records), none are.
   - The script never holds rows.
   - Page every read, at most 10,000 rows per query. Write in chunks with `wrangler d1 execute --remote --file`. It
     runs from a laptop where wrangler is logged in, like `scripts/deploy.mjs`. It can't run in the loop sandbox
     (no credentials), so keep the planning a pure function (rows in, updates out) and test that. The wrangler
     part stays thin.

7. **Keep as is:**
   - which state flips write a change row;
   - the `new_advisory` window and its fixed ids;
   - notify's paging, caps and cursor;
   - every email rule;
   - entry pages;
   - the epss-diff job.

## Tests

- **Age rule, per kind:**
  - an event 30 days old gives `quiet = 'old'` with `event_at` set;
  - 14 days and 13 days old still alert;
  - a missing, unparseable or future date alerts.
- **`public_exploit`:** an old exploit-db signal and a today-dated signal in one batch use the earliest date, so
  the row is `old`.
- **`breach_notice`:** an old `occurredFrom` with a recent `notified` alerts.
- **First-load job:** every change row is `first_load`, and `new_advisory` rows are still dropped.
- **Collector first pass:**
  - a brand-new source gives `first_load`;
  - after an `ok` run, rows alert;
  - after only a step-limit `ok` run, the source is still on its first pass;
  - after an `unchanged` run, rows alert;
  - a source that never returns a cursor finishes its first pass after one `ok` run.
- **Hold:**
  - a run whose two steps write 1,500 alertable rows each: step 2 holds 1,000, logs `changes.held`, and
    `runs.alerts` ends at 2,000;
  - a redelivered step does not count twice.
- **notify:**
  - quiet rows are never queued, by the forward read or the late read;
  - quiet rows sitting before an alertable row don't stop it being read;
  - the existing catch-up tests pass.
- **Home** skips quiet rows.
- **Backlog planner:**
  - fixture rows of each kind and reason give the expected updates;
  - rows that are already quiet are untouched;
  - running it twice changes nothing.
- **Migrations** apply on top of existing data in local D1, and existing rows read as `quiet` null.
- Existing tests pass. If an assertion changes, explain why in PROOF.md.

## Not in scope

- EPSS volume (12,799 rows in three days) and the EPSS licence.
- Showing `event_at` on entry pages.
- Changing which state flips write a change row.
- Running the backlog script. It runs by hand after deploy: staging first, production after the production deploy
  is approved.

## Acceptance criteria

1. `pnpm build` and the Workers tests for the linker, collector, notify, api, loader and the e2b jobs pass, and the
   lockfile is unchanged.
2. On fixtures shaped like the staging table above, the backlog planner marks the old and first-load rows and leaves
   the current ones.
3. No quiet row is ever queued for email or shown on the home page. Every quiet row is still stored and shown on its
   entry page.
4. PROOF.md gives the rollout order (deploy, dry run, `--apply`) and a How to revert with the SQL that un-quiets
   rows.
