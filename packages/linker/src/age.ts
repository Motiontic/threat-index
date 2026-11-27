import type { Row } from './tables';

/** An event older than this many days (by UTC day) before the row was written does not alert. */
export const ALERT_WINDOW_DAYS = 14;
/** Alertable change rows one collector run (or one big-file job) may write; the rest are held. */
export const MAX_ALERTS_PER_RUN = 2000;
export const DAY_MS = 86_400_000;

export type Quiet = 'old' | 'first_load' | 'held';

const dayOf = (iso: string): number | null => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : Math.floor(t / DAY_MS);
};

/**
 * `'old'` when `eventAt`'s day is more than ALERT_WINDOW_DAYS before `at`'s day. Exactly 14 days still alerts.
 * A missing, unparseable or future date never makes a row quiet.
 */
export function ageQuiet(eventAt: string | null | undefined, at: string): 'old' | null {
  if (typeof eventAt !== 'string') return null;
  const e = dayOf(eventAt);
  const a = dayOf(at);
  if (e === null || a === null) return null;
  return a - e > ALERT_WINDOW_DAYS ? 'old' : null;
}

/** Sets `quiet` on a change row, keeping an existing reason. */
export function quietRow(row: Row, reason: Quiet): void {
  if (row.quiet === null || row.quiet === undefined) row.quiet = reason;
}

/** Marks every change row quiet as `first_load` unless it already has a reason. Returns the rows it changed. */
export function firstLoadQuiet(rows: Row[]): number {
  let n = 0;
  for (const r of rows)
    if (r.quiet === null || r.quiet === undefined) {
      r.quiet = 'first_load';
      n++;
    }
  return n;
}

export interface QuietCounts {
  old: number;
  firstLoad: number;
  held: number;
}

export const countQuiet = (rows: Row[]): QuietCounts => ({
  old: rows.filter((r) => r.quiet === 'old').length,
  firstLoad: rows.filter((r) => r.quiet === 'first_load').length,
  held: rows.filter((r) => r.quiet === 'held').length,
});

/**
 * Holds the alertable rows (quiet null) past `limit`, given `already` alertable rows counted earlier in the
 * run. Returns how many are alertable after the hold, and how many it held.
 */
export function holdOver(
  rows: Row[],
  already: number,
  limit: number = MAX_ALERTS_PER_RUN,
): { alerts: number; held: number } {
  let room = Math.max(0, limit - already);
  let alerts = 0;
  let held = 0;
  for (const r of rows) {
    if (r.quiet !== null && r.quiet !== undefined) continue;
    if (room > 0) {
      room--;
      alerts++;
    } else {
      r.quiet = 'held';
      held++;
    }
  }
  return { alerts, held };
}
