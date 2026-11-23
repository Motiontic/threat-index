import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { databaseFor, TABLE_DATABASE } from '../packages/db/src/tables';

const MIGRATIONS = new URL('../packages/db/migrations/', import.meta.url);

describe('TABLE_DATABASE', () => {
  const fromSql: [string, string][] = [];
  for (const dir of readdirSync(MIGRATIONS)) {
    const sql = readFileSync(new URL(`${dir}/0001_init.sql`, MIGRATIONS), 'utf8');
    for (const m of sql.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)/gi))
      fromSql.push([m[1] as string, `ti_${dir}`]);
  }

  it('maps every table in every 0001_init.sql exactly once, to its own database', () => {
    expect(fromSql.length).toBe(22);
    expect(new Set(fromSql.map(([t]) => t)).size).toBe(fromSql.length);
    expect(Object.entries(TABLE_DATABASE).sort()).toEqual([...fromSql].sort());
  });
  it('databaseFor resolves and throws on an unknown table', () => {
    expect(databaseFor('vulns')).toBe('ti_vulns');
    expect(databaseFor('changes')).toBe('ti_signals');
    expect(() => databaseFor('nope')).toThrow(/unknown table/);
    expect(() => databaseFor('toString')).toThrow(/unknown table/);
  });
});
