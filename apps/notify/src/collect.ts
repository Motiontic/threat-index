import type { Env } from './env';
import { FIRST_RUN_WINDOW_HOURS, HOUR_MS, LATE_WINDOW_HOURS, MAX_CHANGES_PER_RUN } from './limits';

export interface Change {
  id: string;
  entity_key: string;
  kind: string;
  old: string | null;
  new: string | null;
  at: string;
  source: string | null;
}
export interface Cursor {
  at: string;
  id: string;
  /** Where the first run started. The late read never goes before it, so history is never mailed. */
  since?: string;
  /** Lower bound (inclusive) of the late read: the first late change not yet matched. Late rows can't age out. */
  late?: { at: string; id: string };
}

export interface Collected {
  /** Forward and late rows together, forward first; may hold duplicates of nothing (ids are unique). */
  changes: Change[];
  forwardCount: number;
  /** Where to continue next run. */
  cursor: Cursor;
  /** The cursor this run started from. */
  start: Cursor;
  /** True when there is no stored cursor row and this is a first run. */
  first: boolean;
  backlog: boolean;
  /** The late read hit its row limit. */
  lateFull: boolean;
}

const COLS = 'id, entity_key, kind, old, new, at, source';

function isLate(v: unknown): v is { at: string; id: string } {
  return (
    typeof v === 'object' &&
    v !== null &&
    typeof (v as Record<string, unknown>).at === 'string' &&
    typeof (v as Record<string, unknown>).id === 'string'
  );
}

function parseCursor(raw: string | undefined): Cursor | null {
  if (!raw) return null;
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    if (typeof j.at === 'string' && typeof j.id === 'string')
      return {
        at: j.at,
        id: j.id,
        ...(typeof j.since === 'string' ? { since: j.since } : {}),
        ...(isLate(j.late) ? { late: { at: j.late.at, id: j.late.id } } : {}),
      };
  } catch {}
  return null;
}

export async function collect(env: Env, runAt: Date): Promise<Collected> {
  const row = await env.DB_USERS.prepare("SELECT value FROM notify_state WHERE name = 'cursor'").first<{
    value: string;
  }>();
  const stored = parseCursor(row?.value);
  const first = stored === null;
  const firstAt = new Date(runAt.getTime() - FIRST_RUN_WINDOW_HOURS * HOUR_MS).toISOString();
  const start: Cursor = stored ?? { at: firstAt, id: '', since: firstAt };

  const forward = (
    await env.DB_SIGNALS.prepare(
      `SELECT ${COLS} FROM changes WHERE at > ?1 OR (at = ?1 AND id > ?2) ORDER BY at, id LIMIT ?3`,
    )
      .bind(start.at, start.id, MAX_CHANGES_PER_RUN)
      .all<Change>()
  ).results;

  // Rows the loader wrote after the cursor passed their time. Not on a first run: that would mail history.
  let late: Change[] = [];
  let lateFull = false;
  if (!first) {
    const back = new Date(Date.parse(start.at) - LATE_WINDOW_HOURS * HOUR_MS).toISOString();
    const floor = start.since && start.since > back ? start.since : back;
    // A stored bound (the first late change not matched yet) keeps it in reach however long it waits. The read
    // starts at the earlier of the bound and the usual floor: a row committed late with an `at` between the two
    // is read again, never skipped for good.
    const stored = start.late && start.late.at >= (start.since ?? '') ? start.late : null;
    const bound = stored && stored.at <= floor ? stored : null;
    late = (
      bound
        ? await env.DB_SIGNALS.prepare(
            `SELECT ${COLS} FROM changes WHERE (at > ?1 OR (at = ?1 AND id >= ?2)) AND at <= ?3 ORDER BY at, id LIMIT ?4`,
          )
            .bind(bound.at, bound.id, start.at, MAX_CHANGES_PER_RUN)
            .all<Change>()
        : await env.DB_SIGNALS.prepare(
            `SELECT ${COLS} FROM changes WHERE at > ?1 AND at <= ?2 ORDER BY at, id LIMIT ?3`,
          )
            .bind(floor, start.at, MAX_CHANGES_PER_RUN)
            .all<Change>()
    ).results;
    lateFull = late.length >= MAX_CHANGES_PER_RUN;
  }

  const seen = new Set(forward.map((c) => c.id));
  const changes = [...forward, ...late.filter((c) => !seen.has(c.id))];
  const last = forward[forward.length - 1];
  return {
    changes,
    forwardCount: forward.length,
    cursor: last ? { at: last.at, id: last.id, ...(start.since ? { since: start.since } : {}) } : start,
    start,
    first,
    backlog: forward.length >= MAX_CHANGES_PER_RUN,
    lateFull,
  };
}
