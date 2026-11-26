/**
 * The tables an inbox chunk may write. Inbox data comes from a sandbox, so nothing in ti_control can be
 * written from it: not licence switches (`sources`), cursors, run and job bookkeeping, or the budget meter.
 * `affected` and `package_advisories` are written by the linker and by the `affected-backfill` job.
 */
export const INBOX_TABLES: ReadonlySet<string> = new Set([
  'vulns',
  'advisories',
  'signals',
  'changes',
  'techniques',
  'vuln_techniques',
  'companies',
  'breach_notices',
  'breach_events',
  'incidents',
  'affected',
  'package_advisories',
]);
