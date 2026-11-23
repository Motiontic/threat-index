import { env } from 'cloudflare:workers';
import { getTableConfig, type SQLiteTable } from 'drizzle-orm/sqlite-core';
import { describe, expect, it } from 'vitest';
import * as advisories from '../src/schema/advisories';
import * as control from '../src/schema/control';
import * as signals from '../src/schema/signals';
import * as users from '../src/schema/users';
import * as vulns from '../src/schema/vulns';
import * as world from '../src/schema/world';

const DBS = [
  ['DB_CONTROL', control],
  ['DB_VULNS', vulns],
  ['DB_ADVISORIES', advisories],
  ['DB_SIGNALS', signals],
  ['DB_WORLD', world],
  ['DB_USERS', users],
] as const;

interface PragmaRow {
  name: string;
  type: string;
  notnull: number;
  pk: number;
}

describe('Drizzle schema matches the SQL migrations', () => {
  for (const [binding, mod] of DBS) {
    const tables = Object.values(mod).map((t) => getTableConfig(t as SQLiteTable));
    it(`${binding}: ${tables.length} tables`, async () => {
      const db = (env as unknown as Record<string, D1Database>)[binding] as D1Database;
      const { results: sqlTables } = await db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'd1_%'",
        )
        .all<{ name: string }>();
      expect(tables.map((t) => t.name).sort()).toEqual(
        sqlTables
          .map((t) => t.name)
          .filter((n) => n !== 'sqlite_sequence')
          .sort(),
      );
      for (const t of tables) {
        const { results } = await db.prepare(`PRAGMA table_info(${t.name})`).all<PragmaRow>();
        const actual = results.map((c) => [
          c.name,
          c.type.toLowerCase(),
          c.notnull === 1 || c.pk > 0,
          c.pk > 0,
        ]);
        const expected = t.columns.map((c) => [
          c.name,
          c.getSQLType(),
          c.notNull || c.primary || t.primaryKeys.some((pk) => pk.columns.includes(c)),
          c.primary || t.primaryKeys.some((pk) => pk.columns.includes(c)),
        ]);
        expect(expected, t.name).toEqual(actual);
      }
    });
  }
});
