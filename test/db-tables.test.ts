import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { databaseFor, TABLE_DATABASE } from '../packages/db/src/tables';

const MIGRATIONS = new URL('../packages/db/migrations/', import.meta.url);

describe('TABLE_DATABASE', () => {
  const fromSql: [string, string][] = [];
  for (const dir of readdirSync(MIGRATIONS)) {
    for (const file of readdirSync(new URL(`${dir}/`, MIGRATIONS)).filter((f) => f.endsWith('.sql'))) {
      const sql = readFileSync(new URL(`${dir}/${file}`, MIGRATIONS), 'utf8');
      for (const m of sql.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)/gi))
        fromSql.push([m[1] as string, `ti_${dir}`]);
    }
  }

  it('maps every table in every migration exactly once, to its own database', () => {
    expect(fromSql.length).toBe(24);
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
