import { describe, expect, it } from 'vitest';
import { DATABASES } from './databases';
import { DB_WRITE_ORDER, TABLES, WRITE_ORDER } from './table-info';
import { databaseFor } from './tables';

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const migrations = (import.meta as unknown as GlobImportMeta).glob('../migrations/*/*.sql', {
  query: '?raw',
  import: 'default',
  eager: true,
});

describe('TABLES', () => {
  const fromSql: [string, string][] = [];
  for (const [path, sql] of Object.entries(migrations)) {
    const dir = path.split('/')[2];
    for (const m of sql.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)/gi))
      fromSql.push([m[1] as string, `ti_${dir}`]);
    // A rebuilt table is created under a temporary name and renamed; only the final name is a table.
    for (const m of sql.matchAll(/ALTER TABLE\s+(\w+)\s+RENAME TO/gi)) {
      const i = fromSql.findIndex(([t]) => t === m[1]);
      if (i > -1) fromSql.splice(i, 1);
    }
  }

  it('has every migration table exactly once, in its own folder database, and nothing else', () => {
    expect(fromSql.length).toBe(31);
    expect(new Set(fromSql.map(([t]) => t)).size).toBe(fromSql.length);
    expect([...TABLES.values()].map((t) => [t.name, t.db]).sort()).toEqual([...fromSql].sort());
  });
  it('agrees with databaseFor', () => {
    for (const t of TABLES.values()) expect(t.db).toBe(databaseFor(t.name));
  });
  it('gives every table a rule, and the right one', () => {
    const rules = Object.fromEntries([...TABLES.values()].map((t) => [t.name, t.rule]));
    expect(rules).toMatchObject({
      vulns: 'newer',
      advisories: 'newer',
      breach_notices: 'newer',
      breach_events: 'newer',
      incidents: 'newer',
      sources: 'newer',
      cursors: 'newer',
      runs: 'upsert',
      jobs: 'upsert',
      techniques: 'upsert',
      vuln_techniques: 'upsert',
      companies: 'upsert',
      signals: 'keep-first-seen',
      changes: 'insert-ignore',
      budget: 'none',
    });
    for (const t of TABLES.values()) {
      if (t.db === 'ti_users') expect(t.rule).toBe('none');
      if (t.rule === 'newer') expect(t.versionColumn).toBeDefined();
    }
    expect(TABLES.get('sources')?.versionColumn).toBe('updated_at');
    expect(TABLES.get('vulns')?.versionColumn).toBe('modified');
  });
  it('knows keys and indexes', () => {
    expect([...(TABLES.get('advisories')?.primaryKey ?? [])].sort()).toEqual(['source', 'source_id']);
    expect(TABLES.get('advisories')?.secondaryIndexes).toBe(1);
    expect(TABLES.get('vulns')?.secondaryIndexes).toBe(0);
    expect(TABLES.get('vulns')?.columns.get('cvss')?.type).toBe('real');
    expect(TABLES.get('vulns')?.columns.get('hot')).toEqual({
      type: 'integer',
      notNull: true,
      hasDefault: true,
    });
  });
  it('WRITE_ORDER lists exactly the writable tables', () => {
    const writable = [...TABLES.values()].filter((t) => t.rule !== 'none').map((t) => t.name);
    expect([...WRITE_ORDER].sort()).toEqual(writable.sort());
    expect(WRITE_ORDER.length).toBe(16);
  });
  it('DB_WRITE_ORDER covers every database a writable table uses', () => {
    expect(DB_WRITE_ORDER).toEqual(['ti_control', 'ti_world', 'ti_signals', 'ti_vulns', 'ti_advisories']);
    expect(DATABASES).toContain('ti_users');
  });
});
