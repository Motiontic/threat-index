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
}

export interface Collected {
  /** Forward and late rows together, forward first; may hold duplicates of nothing (ids are unique). */
  changes: Change[];
  forwardCount: number;
  /** Where to continue next run. */
  cursor: Cursor;
  /** True when there is no stored cursor row and this is a first run. */
  first: boolean;
  backlog: boolean;
}

const COLS = 'id, entity_key, kind, old, new, at, source';

function parseCursor(raw: string | undefined): Cursor | null {
  if (!raw) return null;
  try {
    const j = JSON.parse(raw) as Record<string, unknown>;
    if (typeof j.at === 'string' && typeof j.id === 'string')
      return { at: j.at, id: j.id, ...(typeof j.since === 'string' ? { since: j.since } : {}) };
  } catch {}
  return null;
}

export interface PageFrom {
  /** The cursor the previous page saved. Later pages are forward only: no late read. */
  cursor: Cursor;
}

/** One page: the stored cursor (or `from.cursor`, for pages after the first) forward, plus the late window on the first page only. */
export async function collect(env: Env, runAt: Date, from?: PageFrom): Promise<Collected> {
  let stored: Cursor | null;
  if (from) stored = from.cursor;
  else {
    const row = await env.DB_USERS.prepare("SELECT value FROM notify_state WHERE name = 'cursor'").first<{
      value: string;
    }>();
    stored = parseCursor(row?.value);
  }
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
  if (!first && !from) {
    const back = new Date(Date.parse(start.at) - LATE_WINDOW_HOURS * HOUR_MS).toISOString();
    const from = start.since && start.since > back ? start.since : back;
    late = (
      await env.DB_SIGNALS.prepare(
        `SELECT ${COLS} FROM changes WHERE at > ?1 AND at <= ?2 ORDER BY at, id LIMIT ?3`,
      )
        .bind(from, start.at, MAX_CHANGES_PER_RUN)
        .all<Change>()
    ).results;
  }

  const seen = new Set(forward.map((c) => c.id));
  const changes = [...forward, ...late.filter((c) => !seen.has(c.id))];
  const last = forward[forward.length - 1];
  return {
    changes,
    forwardCount: forward.length,
    cursor: last ? { at: last.at, id: last.id, ...(start.since ? { since: start.since } : {}) } : start,
    first,
    backlog: forward.length >= MAX_CHANGES_PER_RUN,
  };
}
