import { releaseWrites, reserveWrites, type WritePriority } from '@ti/core/budget';
import type { InboxRow } from '@ti/core/inbox';
import type { DatabaseName } from './databases';
import { planWrites } from './plan';
import { DB_WRITE_ORDER } from './table-info';

export type DatabaseMap = Partial<Record<DatabaseName, D1Database>>;

const BINDINGS: Record<string, DatabaseName> = {
  DB_CONTROL: 'ti_control',
  DB_VULNS: 'ti_vulns',
  DB_ADVISORIES: 'ti_advisories',
  DB_SIGNALS: 'ti_signals',
  DB_WORLD: 'ti_world',
  DB_USERS: 'ti_users',
};

/** Maps DB_CONTROL → ti_control, DB_VULNS → ti_vulns, and so on, from a Worker's env. */
export function databasesFromEnv(env: Record<string, unknown>): DatabaseMap {
  const map: DatabaseMap = {};
  for (const [binding, name] of Object.entries(BINDINGS)) {
    const db = env[binding];
    if (db) map[name] = db as D1Database;
  }
  return map;
}

/** A data-row statement failed in D1. Budget and control statements throw their own errors, not this one. */
export class DataWriteError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause), { cause });
    this.name = 'DataWriteError';
  }
}

export interface WriteResult {
  written: number;
  statements: number;
  /** True when a first-load write was not made because today's budget is used up. */
  deferred: boolean;
}

/**
 * Routes each row to its database, writes newer-wins upserts and deletes within the statement and
 * bound-parameter limits, and counts every row in the ti_control budget. Steady writes always proceed;
 * first-load writes stop at the daily cap and return `deferred: true` without writing.
 *
 * Every rule is idempotent, so after a failure a retry is safe. Rows that "newer wins" skips still
 * count, so the meter errs high.
 */
export async function writeRows(
  dbs: DatabaseMap,
  rows: InboxRow[],
  opts: { priority: WritePriority; now?: Date },
): Promise<WriteResult> {
  if (rows.length === 0) return { written: 0, statements: 0, deferred: false };
  const now = opts.now ?? new Date();

  // Validation and database lookup both happen before any I/O.
  const plan = planWrites(rows);
  const control = dbs.ti_control;
  if (!control) throw new Error('writeRows needs ti_control for the budget, but it is missing');
  for (const s of plan.statements) {
    if (!dbs[s.db]) throw new Error(`writeRows needs ${s.db} for table ${s.table}, but it is missing`);
  }

  if (opts.priority === 'first-load') {
    const ok = await reserveWrites(control, plan.cost, 'first-load', now);
    if (!ok) return { written: 0, statements: 0, deferred: true };
  }

  let written = 0;
  try {
    for (const name of DB_WRITE_ORDER) {
      const db = dbs[name];
      const stmts = plan.statements.filter((s) => s.db === name);
      if (!db || stmts.length === 0) continue;
      let results: D1Result[];
      try {
        results = await db.batch(stmts.map((s) => db.prepare(s.sql).bind(...s.params)));
      } catch (err) {
        throw new DataWriteError(err);
      }
      for (const r of results) written += r.meta.changes ?? 0;
    }
  } catch (err) {
    if (opts.priority === 'first-load') {
      try {
        await releaseWrites(control, plan.cost, now);
      } catch (releaseErr) {
        console.error(
          JSON.stringify({ event: 'release_failed', cost: plan.cost, error: String(releaseErr) }),
        );
      }
    }
    throw err;
  }

  if (opts.priority === 'steady') await reserveWrites(control, plan.cost, 'steady', now);
  return { written, statements: plan.statements.length, deferred: false };
}
