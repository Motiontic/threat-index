import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core';
import type { DatabaseName } from './databases';
import * as advisories from './schema/advisories';
import * as control from './schema/control';
import * as signals from './schema/signals';
import * as users from './schema/users';
import * as vulns from './schema/vulns';
import * as world from './schema/world';

const SCHEMAS: [DatabaseName, Record<string, unknown>][] = [
  ['ti_control', control],
  ['ti_vulns', vulns],
  ['ti_advisories', advisories],
  ['ti_signals', signals],
  ['ti_world', world],
  ['ti_users', users],
];

function build(): Record<string, DatabaseName> {
  const map: Record<string, DatabaseName> = {};
  for (const [db, mod] of SCHEMAS) {
    for (const t of Object.values(mod)) {
      const name = getTableConfig(t as SQLiteTable).name;
      if (map[name]) throw new Error(`table ${name} is in both ${map[name]} and ${db}`);
      map[name] = db;
    }
  }
  return map;
}

/** Which database each table lives in, derived from the Drizzle schemas in ./schema. */
export const TABLE_DATABASE: Readonly<Record<string, DatabaseName>> = Object.freeze(build());

export function databaseFor(table: string): DatabaseName {
  const db = Object.hasOwn(TABLE_DATABASE, table) ? TABLE_DATABASE[table] : undefined;
  if (!db) throw new Error(`unknown table: ${table}`);
  return db;
}
