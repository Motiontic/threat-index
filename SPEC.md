# notify-catchup: read more than 500 changes a run, and say when notify falls behind

## Why

notify reads at most `MAX_CHANGES_PER_RUN` (500) forward changes per run (`apps/notify/src/collect.ts`), and it runs
once per collector run, every 3 hours (`run-finished` message from the collector's planner). That is at most 4,000
changes a day.

Source loads wrote far more than that from 24 to 26 Nov:

| Environment | Changes written 24–26 Nov | Most changes sharing one `at` | Cursor on 27 Nov 15:00 UTC |
| --- | --- | --- | --- |
| staging | about 82,000 (53,619 on 24 Nov) | 12,641 | `at` 2026-11-24T00:02:37.699Z; 69,256 changes still ahead of it |
| production | about 86,700 (73,488 on 24 Nov) | 12,641 | `at` 2026-11-24T06:04:25.616Z |

Most of these are `public_exploit` (exploit-db, Metasploit), `fix_released` (GitHub advisories, MSRC, Debian) and
`epss_band` rows.

At 4,000 a day, a change written today won't be read for about three weeks. The cursor looked stuck because
thousands of changes share one `at` value: each run moves only the id part of the cursor, by 500 rows. It's moving,
just far too slowly.

Each run also re-reads the late window, up to 500 rows at or before the cursor's time. While notify is behind, those
are rows it has already matched, and the 15:00 run logged `changes: 1000` for 500 new rows.

## What to build

1. **Several pages per run.** After the first page, read the next forward page from the cursor the previous page
   saved, and match and queue it, until one of these happens:
   - a page returns fewer than `MAX_CHANGES_PER_RUN` rows (caught up);
   - `MAX_PAGES_PER_RUN` pages are done (new constant in `limits.ts`; see item 4 for its value);
   - a wall-time budget is used up, measured from the start of the run (new constant, start at 4 minutes). Check it
     before starting each new page. The clock comes from `deps.now`, so tests can drive it.

   Each page saves its cursor in the same D1 batch as its queue inserts, as `matchAndQueue` already does. If page 3
   fails, the progress from pages 1 and 2 stays.
2. **Late read once per run.** Only the first page includes the late window. Later pages are forward only.
3. **Structure.** `collect` reads one page from a given cursor. `runNotify` loops over pages. Planning, rendering and
   sending (steps 3–5) still run once, after the last page, as today. Watchlist notices still go first.
4. **D1 budget.** Measure D1 calls per page in a test, with entry watches, package watches and saved searches all
   present. Count them the way Cloudflare does (round 2 decision 1): each `first()`, `all()` or `run()` is one call,
   and each `batch()` is one call however many statements it holds. Set `MAX_PAGES_PER_RUN` to 8. Show in a test
   that one whole run stays under 500 D1 calls: all 8 pages, plus planning, `MAX_EMAILS_PER_RUN` sends, notices and
   the digest-hour prune. Put the measured numbers in PROOF.md, with the D1 calls per page and per send.
5. **Say when it's behind.** When a run stops with forward rows still unread (page or time budget), log
   `{"event":"notify.behind","pages":N,"read":R,"lagHours":H}`. `lagHours` is runAt minus the cursor's `at`, in
   hours, with one decimal place. Add `pages` to the existing `notify.run` log. Logs never contain user IDs, email
   addresses or change contents.
6. **Keep as is:**
   - the page size (500), the cursor format and the `since` rule;
   - the late-window and first-run rules;
   - every email cap and rule;
   - the queue retry on failure.

## Tests

- 1,300 forward changes that share one `at`: one run reads three pages (500, 500 and 300). The saved cursor is the
  last row's `(at, id)`. The next run reads no forward rows.
- Page budget: with more rows than `MAX_PAGES_PER_RUN` × 500, the run stops after that many pages. It logs
  `notify.behind` and leaves the cursor at the last page's last row. The next run carries on from there, and no
  change is queued twice.
- Time budget: with an injected clock that passes the budget after page 1, the run stops after page 1.
- The late read happens once per run, on the first page only.
- Page 2's batch fails: page 1's cursor and queue rows stay, the message is retried, and the retry queues no
  duplicates.
- The D1 call count test from item 4.
- Existing notify tests pass. If an assertion changes because a run can now read more than one page, explain why in
  PROOF.md.

## Not in scope

- Whether a source's first load should write change rows at all. That's a linker question for a separate change.
- The cron schedule and the collector's message.
- Skipping or deleting the current backlog.

## Acceptance criteria

1. `pnpm build` and the Workers tests for `apps/notify` pass; the lockfile is unchanged.
2. One run reads up to `MAX_PAGES_PER_RUN` × 500 forward changes and saves the cursor after every page.
3. `notify.behind` is logged whenever a run stops with rows still unread.
4. D1 calls per run are measured and stay under 500.

## Round 2 decisions

1. **Count D1 calls the way Cloudflare does.** On Workers Paid, Cloudflare allows 1,000 D1 queries per Worker
   invocation, and "a `db.batch()` call counts as a single query against it, not one query per statement" (D1
   limits page, Batch limits section). Round 1 counted each statement in a batch as well, which made the 500
   ceiling impossible even before this change. Count each `batch()` as one call. The 500 ceiling stays, as half of
   Cloudflare's limit.
2. **`MAX_PAGES_PER_RUN` is 8.** If the corrected count of a whole run with 8 pages still goes over 500, stop and
   report the numbers. Don't lower the page count on your own.
3. **Keep the round 1 work.** The page loop, the per-page cursor save, the late read on page 1 only, `notify.behind`
   and the time budget are already in the worktree (uncommitted). Keep them, fix the count test, then run the
   existing notify tests, `pnpm build` and the lockfile check.
