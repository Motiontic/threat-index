import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core';
import type { DatabaseName } from './databases';
import * as advisories from './schema/advisories';
import * as control from './schema/control';
import * as signals from './schema/signals';
import * as users from './schema/users';
import * as vulns from './schema/vulns';
import * as world from './schema/world';
import { databaseFor } from './tables';

/** What the writer does when a row's key already exists. See docs in the loader-budget SPEC. */
export type WriteRule = 'newer' | 'upsert' | 'keep-first-seen' | 'insert-ignore' | 'none';

export interface ColumnInfo {
  type: 'text' | 'integer' | 'real';
  notNull: boolean;
  hasDefault: boolean;
}

export interface TableInfo {
  name: string;
  db: DatabaseName;
  columns: ReadonlyMap<string, ColumnInfo>;
  primaryKey: readonly string[];
  secondaryIndexes: number;
  rule: WriteRule;
  versionColumn?: 'modified' | 'updated_at';
}

/** Rules for tables that have no `modified` or `updated_at` column to compare. */
const OTHER_RULES: Record<string, WriteRule> = {
  runs: 'upsert',
  jobs: 'upsert',
  techniques: 'upsert',
  vuln_techniques: 'upsert',
  companies: 'upsert',
  signals: 'keep-first-seen',
  changes: 'insert-ignore',
  budget: 'none',
};

/** Only budget.ts writes the meter and only the API writes accounts. */
const NEVER_WRITTEN = new Set(['budget']);

const SCHEMAS: [DatabaseName, Record<string, unknown>][] = [
  ['ti_control', control],
  ['ti_vulns', vulns],
  ['ti_advisories', advisories],
  ['ti_signals', signals],
  ['ti_world', world],
  ['ti_users', users],
];

function build(): Map<string, TableInfo> {
  const map = new Map<string, TableInfo>();
  for (const [db, mod] of SCHEMAS) {
    for (const t of Object.values(mod)) {
      const cfg = getTableConfig(t as SQLiteTable);
      const columns = new Map<string, ColumnInfo>();
      const pk = new Set<string>();
      for (const c of cfg.columns) {
        const type = c.getSQLType();
        if (type !== 'text' && type !== 'integer' && type !== 'real')
          throw new Error(`${cfg.name}.${c.name}: unsupported column type ${type}`);
        columns.set(c.name, { type, notNull: c.notNull, hasDefault: c.hasDefault });
        if (c.primary) pk.add(c.name);
      }
      for (const k of cfg.primaryKeys) for (const c of k.columns) pk.add(c.name);
      const versionColumn = columns.has('modified')
        ? 'modified'
        : columns.has('updated_at')
          ? 'updated_at'
          : undefined;
      let rule: WriteRule;
      if (db === 'ti_users' || NEVER_WRITTEN.has(cfg.name)) rule = 'none';
      else if (versionColumn) rule = 'newer';
      else rule = OTHER_RULES[cfg.name] ?? 'none';
      if (map.has(cfg.name)) throw new Error(`table ${cfg.name} is defined twice`);
      const info: TableInfo = {
        name: cfg.name,
        db,
        columns,
        primaryKey: [...pk],
        secondaryIndexes: cfg.indexes.length,
        rule,
        ...(rule === 'newer' && versionColumn ? { versionColumn } : {}),
      };
      if (databaseFor(cfg.name) !== db) throw new Error(`${cfg.name}: database mismatch`);
      map.set(cfg.name, info);
    }
  }
  return map;
}

export const TABLES: ReadonlyMap<string, TableInfo> = build();

/** Every writable table, in the order a call's statements are issued. */
export const WRITE_ORDER: readonly string[] = [
  'sources',
  'cursors',
  'runs',
  'jobs',
  'techniques',
  'companies',
  'vuln_techniques',
  'breach_events',
  'breach_notices',
  'incidents',
  'signals',
  'changes',
  'vulns',
  'advisories',
];

/** The order a call's databases are written in. */
export const DB_WRITE_ORDER: readonly DatabaseName[] = [
  'ti_control',
  'ti_world',
  'ti_signals',
  'ti_vulns',
  'ti_advisories',
];
