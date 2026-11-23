import { describe, expect, it } from 'vitest';
import { databasesFromEnv, writeRows } from './write';

describe('databasesFromEnv', () => {
  it('maps each DB_* binding to its database and ignores everything else', () => {
    const control = {} as D1Database;
    const vulns = {} as D1Database;
    const dbs = databasesFromEnv({ DB_CONTROL: control, DB_VULNS: vulns, BUCKET: {}, JOB_HMAC_SECRET: 'x' });
    expect(dbs).toEqual({ ti_control: control, ti_vulns: vulns });
    expect(dbs.ti_control).toBe(control);
  });
  it('maps all six', () => {
    const env = Object.fromEntries(
      ['CONTROL', 'VULNS', 'ADVISORIES', 'SIGNALS', 'WORLD', 'USERS'].map((n) => [`DB_${n}`, { n }]),
    );
    expect(Object.keys(databasesFromEnv(env)).sort()).toEqual([
      'ti_advisories',
      'ti_control',
      'ti_signals',
      'ti_users',
      'ti_vulns',
      'ti_world',
    ]);
  });
});

describe('writeRows (no D1 needed)', () => {
  it('returns at once for no rows, with no queries', async () => {
    expect(await writeRows({}, [], { priority: 'steady' })).toEqual({
      written: 0,
      statements: 0,
      deferred: false,
    });
  });
  it('names a missing database before any I/O', async () => {
    const rows = [
      { table: 'changes', op: 'upsert' as const, row: { id: 'x', entity_key: 'k', kind: 'k', at: 't' } },
    ];
    await expect(writeRows({}, rows, { priority: 'steady' })).rejects.toThrow(/ti_control/);
    await expect(writeRows({ ti_control: {} as D1Database }, rows, { priority: 'steady' })).rejects.toThrow(
      /ti_signals/,
    );
  });
});
