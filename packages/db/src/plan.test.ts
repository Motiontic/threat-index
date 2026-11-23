import { type InboxRow, MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import { describe, expect, it } from 'vitest';
import { MAX_PARAM_BYTES, planWrites, RowValidationError, WriteLimitError } from './plan';
import { jsonDeleteSql, jsonUpsertSql, MAX_STATEMENTS_PER_INVOCATION } from './sql';
import { TABLES } from './table-info';

const vuln = (key: string, extra: Record<string, unknown> = {}): InboxRow => ({
  table: 'vulns',
  op: 'upsert',
  row: { key, kind: 'cve', title: 't', modified: '2026-01-01T00:00:00Z', ...extra },
});
const adv = (id: string): InboxRow => ({
  table: 'advisories',
  op: 'upsert',
  row: { source: 's', source_id: id, modified: '2026-01-01' },
});

function reject(rows: unknown[], re: RegExp) {
  let err: unknown;
  try {
    planWrites(rows as InboxRow[]);
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(RowValidationError);
  expect((err as Error).message).toMatch(re);
  return err as RowValidationError;
}

describe('planWrites rejections', () => {
  it('unknown table, none tables and bad shapes', () => {
    reject([{ table: 'nope', op: 'upsert', row: {} }], /unknown table/);
    reject([{ table: 'toString', op: 'upsert', row: {} }], /unknown table/);
    reject([{ table: 'budget', op: 'upsert', row: { day: 'd' } }], /cannot be written/);
    reject([{ table: 'users', op: 'upsert', row: { id: 'x' } }], /cannot be written/);
    reject([{ table: 'vulns', op: 'merge', row: {} }], /op must be/);
    reject([{ table: 'vulns', op: 'upsert', row: [] }], /plain object/);
    reject([{ table: 'vulns', op: 'upsert', row: new Date() }], /plain object/);
    reject([null], /not an object/);
  });
  it('unknown column, missing key, null key, missing NOT NULL column', () => {
    reject([vuln('a', { bogus: 1 })], /unknown column/);
    reject([vuln('a', { constructor: 1 })], /unknown column/);
    reject([{ table: 'vulns', op: 'upsert', row: { kind: 'c', title: 't', modified: 'm' } }], /primary key/);
    reject([vuln('a', { key: null })], /primary key/);
    reject(
      [{ table: 'vulns', op: 'upsert', row: { key: 'a', kind: 'c', modified: 'm' } }],
      /NOT NULL column missing/,
    );
    reject([vuln('a', { title: null })], /NOT NULL/);
  });
  it('a delete carries only key columns', () => {
    reject(
      [{ table: 'advisories', op: 'delete', row: { source: 's', source_id: 'i', status: 'x' } }],
      /only key/,
    );
    reject([{ table: 'advisories', op: 'delete', row: { source: 's' } }], /primary key/);
  });
  it('bad values', () => {
    reject([vuln('a', { summary: undefined })], /unsupported undefined/);
    reject([vuln('a', { cvss: Number.NaN })], /not finite/);
    reject([vuln('a', { cvss: Number.POSITIVE_INFINITY })], /not finite/);
    reject([vuln('a', { summary: 5 })], /number in a text/);
    reject([vuln('a', { cvss: '7.5' })], /string in a number/);
    reject([vuln('a', { hot: 1.5 })], /safe integer/);
    reject([vuln('a', { hot: 2 ** 60 })], /safe integer/);
    reject([vuln('a', { cvss: true })], /boolean/);
    reject([vuln('a', { summary: 10n })], /bigint/);
    reject([vuln('a', { summary: () => 1 })], /function/);
    reject([vuln('a', { cvss: [1] })], /outside a text/);
    reject([vuln('a', { summary: new Date() })], /unsupported object/);
  });
  it('undefined in a present key is treated as missing', () => {
    reject([vuln('a', { title: undefined })], /NOT NULL column missing/);
  });
  it('names index, table and column but never the value', () => {
    const err = reject([vuln('ok'), vuln('a', { cvss: 'SECRET-VALUE' })], /row 1 \(vulns\.cvss\)/);
    expect(err.index).toBe(1);
    expect(err.table).toBe('vulns');
    expect(err.message).not.toContain('SECRET-VALUE');
  });
  it('one row over the size limit', () => {
    const err = reject([vuln('a'), vuln('b', { summary: 'x'.repeat(MAX_PARAM_BYTES) })], /size limit/);
    expect(err.index).toBe(1);
  });
});

describe('planWrites values', () => {
  const param = (row: InboxRow) => JSON.parse(planWrites([row]).statements[0]?.params[0] as string)[0];
  it('stores booleans as 1/0 and arrays/objects as JSON text in text columns', () => {
    expect(
      param(vuln('a', { ransomware: true, hot: false, sources: ['x', 'y'], cwe: { a: 1 }, summary: null })),
    ).toEqual({
      key: 'a',
      kind: 'cve',
      title: 't',
      modified: '2026-01-01T00:00:00Z',
      ransomware: 1,
      hot: 0,
      sources: '["x","y"]',
      cwe: '{"a":1}',
      summary: null,
    });
  });
  it('accepts integers and reals', () => {
    expect(param(vuln('a', { cvss: 7.5, epss: 1, hot: 0 })).cvss).toBe(7.5);
  });
});

describe('planWrites limits', () => {
  it('501 rows', () => {
    const rows = Array.from({ length: MAX_ROWS_PER_CHUNK + 1 }, (_, i) => vuln(`k${i}`));
    expect(() => planWrites(rows)).toThrow(WriteLimitError);
    expect(() => planWrites(rows.slice(0, MAX_ROWS_PER_CHUNK))).not.toThrow();
  });
  it('a 500-row vulns group with 300-character summaries fits the statement limit, one parameter each', () => {
    const rows = Array.from({ length: 500 }, (_, i) => vuln(`k${i}`, { summary: 's'.repeat(300) }));
    const plan = planWrites(rows);
    expect(plan.statements.length).toBeLessThanOrEqual(MAX_STATEMENTS_PER_INVOCATION);
    expect(plan.statements.length).toBe(1);
    for (const s of plan.statements) {
      expect(s.params.length).toBe(1);
      expect(new TextEncoder().encode(s.params[0]).length).toBeLessThanOrEqual(MAX_PARAM_BYTES);
    }
    expect(plan.rows).toBe(500);
    expect(plan.cost).toBe(500);
  });
  it('splits a group before the JSON passes MAX_PARAM_BYTES', () => {
    const big = 'é'.repeat(90_000); // 2 bytes each in UTF-8
    const rows = Array.from({ length: 12 }, (_, i) => vuln(`k${i}`, { summary: big }));
    const plan = planWrites(rows);
    expect(plan.statements.length).toBeGreaterThan(1);
    expect(plan.statements.reduce((n, s) => n + s.rows, 0)).toBe(12);
    for (const s of plan.statements) {
      expect(new TextEncoder().encode(s.params[0]).length).toBeLessThanOrEqual(MAX_PARAM_BYTES);
      expect(JSON.parse(s.params[0]).length).toBe(s.rows);
    }
  });
  it('41 groups is a WriteLimitError, 40 is fine', () => {
    // Each distinct column set is its own group.
    const cols = Array.from({ length: 41 }, (_, i) => `c${i}`);
    expect(cols.length).toBe(41);
    const withCols = (n: number) =>
      Array.from({ length: n }, (_, i) => {
        const extra: Record<string, unknown> = {};
        // 5 optional vulns columns give distinct subsets: build subset i from its bits.
        ['summary', 'published', 'cvss', 'cwe', 'epss', 'docKey'].forEach((c, b) => {
          const name = c === 'docKey' ? 'doc_key' : c;
          if ((i >> b) & 1) extra[name] = c === 'cvss' || c === 'epss' ? 1 : 'x';
        });
        return vuln(`k${i}`, extra);
      });
    expect(planWrites(withCols(40)).statements.length).toBe(40);
    expect(() => planWrites(withCols(41))).toThrow(WriteLimitError);
  });
});

describe('planWrites grouping, order and duplicates', () => {
  it('a row updates only its own columns: different column sets are different statements', () => {
    const plan = planWrites([vuln('a'), vuln('b', { summary: 's' })]);
    expect(plan.statements.length).toBe(2);
  });
  it('orders by WRITE_ORDER, upserts before deletes', () => {
    const plan = planWrites([
      adv('1'),
      { table: 'advisories', op: 'delete', row: { source: 's', source_id: '2' } },
      vuln('a'),
      { table: 'companies', op: 'upsert', row: { key: 'c', name: 'n' } },
    ]);
    expect(plan.statements.map((s) => `${s.table}:${s.op}`)).toEqual([
      'companies:upsert',
      'vulns:upsert',
      'advisories:upsert',
      'advisories:delete',
    ]);
    expect(plan.statements.map((s) => s.db)).toEqual([
      'ti_world',
      'ti_vulns',
      'ti_advisories',
      'ti_advisories',
    ]);
  });
  it('the last row for a key wins, whatever the grouping', () => {
    const plan = planWrites([
      vuln('a', { title: 'first' }),
      vuln('b'),
      vuln('a', { title: 'last', summary: 's' }),
    ]);
    expect(plan.rows).toBe(2);
    const all = plan.statements.flatMap((s) => JSON.parse(s.params[0]));
    expect(all.filter((r: { key: string }) => r.key === 'a')).toEqual([
      expect.objectContaining({ title: 'last' }),
    ]);
  });
  it('an upsert then a delete of one key leaves only the delete', () => {
    const plan = planWrites([
      adv('1'),
      { table: 'advisories', op: 'delete', row: { source: 's', source_id: '1' } },
    ]);
    expect(plan.statements.map((s) => s.op)).toEqual(['delete']);
  });
});

describe('planWrites cost', () => {
  it('counts index writes: an advisories row costs 2, a vulns row 1, a changes row 2', () => {
    expect(planWrites([adv('1')]).cost).toBe(2);
    expect(planWrites([vuln('1')]).cost).toBe(1);
    expect(
      planWrites([
        { table: 'changes', op: 'upsert', row: { id: 'u', entity_key: 'k', kind: 'epss_band', at: 't' } },
      ]).cost,
    ).toBe(2);
    expect(planWrites([adv('1'), adv('2'), vuln('1')]).cost).toBe(5);
  });
  it('is zero for no rows', () => {
    expect(planWrites([])).toEqual({ statements: [], rows: 0, cost: 0 });
  });
});

describe('SQL for each rule', () => {
  const t = (n: string) => TABLES.get(n) as NonNullable<ReturnType<typeof TABLES.get>>;
  it('newer', () => {
    expect(jsonUpsertSql(t('vulns'), ['key', 'kind', 'modified'])).toBe(
      "INSERT INTO vulns (key, kind, modified) SELECT json_extract(value, '$.key'), json_extract(value, '$.kind'), json_extract(value, '$.modified') FROM json_each(?1) WHERE true ON CONFLICT (key) DO UPDATE SET kind = excluded.kind, modified = excluded.modified WHERE excluded.modified > vulns.modified",
    );
    expect(jsonUpsertSql(t('cursors'), ['source_id', 'updated_at'])).toContain(
      'DO UPDATE SET updated_at = excluded.updated_at WHERE excluded.updated_at > cursors.updated_at',
    );
  });
  it('upsert, with and without non-key columns', () => {
    expect(jsonUpsertSql(t('companies'), ['key', 'name'])).toContain(
      'ON CONFLICT (key) DO UPDATE SET name = excluded.name',
    );
    expect(jsonUpsertSql(t('companies'), ['key'])).toMatch(/ON CONFLICT \(key\) DO NOTHING$/);
    expect(jsonUpsertSql(t('companies'), ['key', 'name'])).not.toContain('excluded.modified');
  });
  it('keep-first-seen never updates first_seen', () => {
    const sql = jsonUpsertSql(t('signals'), ['vuln_key', 'kind', 'source', 'ref', 'first_seen', 'url']);
    expect(sql).toContain('DO UPDATE SET url = excluded.url');
    expect(sql).not.toContain('first_seen = excluded');
    expect(jsonUpsertSql(t('signals'), ['vuln_key', 'kind', 'source', 'ref', 'first_seen'])).toMatch(
      /DO NOTHING$/,
    );
  });
  it('insert-ignore', () => {
    expect(jsonUpsertSql(t('changes'), ['id', 'at'])).toMatch(/ON CONFLICT \(id\) DO NOTHING$/);
  });
  it('delete', () => {
    expect(jsonDeleteSql(t('advisories'))).toBe(
      "DELETE FROM advisories WHERE (source, source_id) IN (SELECT json_extract(value, '$.source'), json_extract(value, '$.source_id') FROM json_each(?1))",
    );
  });
  it('names in SQL come from the schema, never from row data', () => {
    const plan = planWrites([vuln('a; DROP TABLE vulns')]);
    expect(plan.statements[0]?.sql).not.toContain('DROP');
  });
});
