import type { WritePriority } from '@ti/core/budget';
import { NotImplementedError } from '@ti/core/errors';
import type { InboxRow } from '@ti/core/inbox';
import type { DatabaseName } from './databases';

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

export interface WriteResult {
  written: number;
  statements: number;
  /** True when a first-load write was not made because today's budget is used up. */
  deferred: boolean;
}

/**
 * Routes each row to its database, writes newer-wins upserts and deletes within the statement and
 * bound-parameter limits, and counts every row in the ti_control budget. Steady writes always proceed.
 */
export async function writeRows(
  _dbs: DatabaseMap,
  _rows: InboxRow[],
  _opts: { priority: WritePriority; now?: Date },
): Promise<WriteResult> {
  throw new NotImplementedError('db writeRows');
}
