import { NotImplementedError } from '@ti/core/errors';
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

it('writeRows() is a stub until the loader feature fills it in', async () => {
  await expect(writeRows({}, [], { priority: 'steady' })).rejects.toBeInstanceOf(NotImplementedError);
});
