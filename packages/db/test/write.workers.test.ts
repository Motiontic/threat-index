import { env } from 'cloudflare:workers';
import { FIRST_LOAD_DAILY_CAP, reserveWrites } from '@ti/core/budget';
import type { InboxRow } from '@ti/core/inbox';
import { beforeEach, describe, expect, it } from 'vitest';
import { RowValidationError } from '../src/plan';
import { type DatabaseMap, databasesFromEnv, writeRows } from '../src/write';

const NOW = new Date('2026-11-23T12:00:00Z');
const T1 = '2026-01-01T00:00:00Z';
const T2 = '2026-02-01T00:00:00Z';
const T3 = '2026-03-01T00:00:00Z';

const base = databasesFromEnv(env as unknown as Record<string, unknown>);
const control = env.DB_CONTROL;

/** Wraps each database so the test can count batch() calls per database. */
function counting(): { dbs: DatabaseMap; batches: Record<string, number> } {
  const batches: Record<string, number> = {};
  const dbs: DatabaseMap = {};
  for (const [name, db] of Object.entries(base) as [keyof DatabaseMap, D1Database][]) {
    dbs[name] = {
      prepare: (q: string) => db.prepare(q),
      batch: (s: D1PreparedStatement[]) => {
        batches[name] = (batches[name] ?? 0) + 1;
        return db.batch(s);
      },
    } as unknown as D1Database;
  }
  return { dbs, batches };
}

const vuln = (key: string, extra: Record<string, unknown> = {}): InboxRow => ({
  table: 'vulns',
  op: 'upsert',
  row: { key, kind: 'cve', title: `title ${key}`, modified: T2, ...extra },
});
const adv = (id: string, extra: Record<string, unknown> = {}): InboxRow => ({
  table: 'advisories',
  op: 'upsert',
  row: { source: 'nvd', source_id: id, modified: T2, ...extra },
});

const one = async <T>(db: D1Database, sql: string, ...args: unknown[]) =>
  (await db
    .prepare(sql)
    .bind(...args)
    .first<T>()) as T;
const meter = async () =>
  (await control.prepare('SELECT d1_writes AS n FROM budget').first<{ n: number }>())?.n;
const count = async (db: D1Database, table: string) =>
  (await one<{ n: number }>(db, `SELECT count(*) AS n FROM ${table}`)).n;

beforeEach(async () => {
  for (const [db, tables] of [
    [env.DB_CONTROL, ['budget', 'sources', 'cursors', 'runs', 'jobs']],
    [env.DB_VULNS, ['vulns']],
    [env.DB_ADVISORIES, ['advisories']],
    [env.DB_SIGNALS, ['signals', 'changes']],
    [
      env.DB_WORLD,
      ['techniques', 'vuln_techniques', 'companies', 'breach_notices', 'breach_events', 'incidents'],
    ],
  ] as const)
    for (const t of tables) await db.prepare(`DELETE FROM ${t}`).run();
});

describe('writeRows: one batch per database', () => {
  it('writes rows to their databases with one batch() each, in one pass', async () => {
    const { dbs, batches } = counting();
    const rows: InboxRow[] = [
      vuln('a'),
      vuln('b', { summary: 'x' }),
      adv('1'),
      { table: 'companies', op: 'upsert', row: { key: 'c', name: 'C' } },
      { table: 'techniques', op: 'upsert', row: { id: 'T1', framework: 'attack', name: 'N' } },
      {
        table: 'signals',
        op: 'upsert',
        row: { vuln_key: 'a', kind: 'poc', source: 's', ref: 'r', first_seen: T1 },
      },
    ];
    const res = await writeRows(dbs, rows, { priority: 'steady', now: NOW });
    expect(batches).toEqual({ ti_world: 1, ti_signals: 1, ti_vulns: 1, ti_advisories: 1 });
    expect(res.deferred).toBe(false);
    expect(res.statements).toBe(6);
    expect(res.written).toBeGreaterThanOrEqual(6); // one per row; production D1 also counts index entries
    expect(await count(env.DB_VULNS, 'vulns')).toBe(2);
    expect(await count(env.DB_WORLD, 'companies')).toBe(1);
    expect(await count(env.DB_SIGNALS, 'signals')).toBe(1);
    expect(await count(env.DB_ADVISORIES, 'advisories')).toBe(1);
  });

  it('loads a 500-row vulns chunk with 300-character summaries in one call', async () => {
    const rows = Array.from({ length: 500 }, (_, i) => vuln(`k${i}`, { summary: 's'.repeat(300) }));
    const { dbs, batches } = counting();
    const res = await writeRows(dbs, rows, { priority: 'steady', now: NOW });
    expect(res.statements).toBe(1);
    expect(batches).toEqual({ ti_vulns: 1 });
    expect(await count(env.DB_VULNS, 'vulns')).toBe(500);
    expect(await meter()).toBe(500);
  });
});

describe('writeRows: rules', () => {
  it('newer wins: equal or older versions change nothing, newer ones update', async () => {
    await writeRows(base, [vuln('a', { title: 'v2', modified: T2 })], { priority: 'steady', now: NOW });
    await writeRows(base, [vuln('a', { title: 'older', modified: T1 })], { priority: 'steady', now: NOW });
    await writeRows(base, [vuln('a', { title: 'equal', modified: T2 })], { priority: 'steady', now: NOW });
    expect(
      (await one<{ title: string }>(env.DB_VULNS, "SELECT title FROM vulns WHERE key = 'a'")).title,
    ).toBe('v2');
    await writeRows(base, [vuln('a', { title: 'v3', modified: T3 })], { priority: 'steady', now: NOW });
    const row = await one<{ title: string; modified: string }>(
      env.DB_VULNS,
      "SELECT * FROM vulns WHERE key = 'a'",
    );
    expect([row.title, row.modified]).toEqual(['v3', T3]);
  });

  it('a partial row updates only its columns', async () => {
    await writeRows(base, [vuln('a', { summary: 'keep me', cvss: 5 })], { priority: 'steady', now: NOW });
    await writeRows(base, [vuln('a', { title: 'new title', modified: T3 })], {
      priority: 'steady',
      now: NOW,
    });
    const row = await one<Record<string, unknown>>(env.DB_VULNS, "SELECT * FROM vulns WHERE key = 'a'");
    expect(row).toMatchObject({ title: 'new title', summary: 'keep me', cvss: 5, modified: T3 });
  });

  it('an older cursor from an older job never wins (sources/cursors are refused from the inbox but newer on write)', async () => {
    const cursor = (v: string, at: string): InboxRow => ({
      table: 'cursors',
      op: 'upsert',
      row: { source_id: 's', kind: 'k', value: v, updated_at: at },
    });
    await writeRows(base, [cursor('new', T2)], { priority: 'steady', now: NOW });
    await writeRows(base, [cursor('old', T1)], { priority: 'steady', now: NOW });
    expect((await one<{ value: string }>(control, 'SELECT value FROM cursors')).value).toBe('new');
  });

  it('upsert updates supplied columns', async () => {
    const co = (name: string, extra = {}): InboxRow => ({
      table: 'companies',
      op: 'upsert',
      row: { key: 'c', name, ...extra },
    });
    await writeRows(base, [co('A', { ticker: 'T' })], { priority: 'steady', now: NOW });
    await writeRows(base, [co('B')], { priority: 'steady', now: NOW });
    expect(await one(env.DB_WORLD, 'SELECT name, ticker FROM companies')).toEqual({ name: 'B', ticker: 'T' });
    const link = (extra = {}): InboxRow => ({
      table: 'vuln_techniques',
      op: 'upsert',
      row: { vuln_key: 'a', technique_id: 'T1', ...extra },
    });
    await writeRows(base, [link({ origin: 'ai' })], { priority: 'steady', now: NOW });
    await writeRows(base, [link()], { priority: 'steady', now: NOW }); // key only: DO NOTHING
    expect(await one(env.DB_WORLD, 'SELECT origin FROM vuln_techniques')).toEqual({ origin: 'ai' });
  });

  it('keep-first-seen never updates first_seen', async () => {
    const sig = (first: string, url: string): InboxRow => ({
      table: 'signals',
      op: 'upsert',
      row: { vuln_key: 'a', kind: 'poc', source: 's', ref: 'r', first_seen: first, url },
    });
    await writeRows(base, [sig(T1, 'u1')], { priority: 'steady', now: NOW });
    await writeRows(base, [sig(T3, 'u2')], { priority: 'steady', now: NOW });
    expect(await one(env.DB_SIGNALS, 'SELECT first_seen, url FROM signals')).toEqual({
      first_seen: T1,
      url: 'u2',
    });
  });

  it('insert-ignore: a redelivered change is a no-op', async () => {
    const ch = (kind: string): InboxRow => ({
      table: 'changes',
      op: 'upsert',
      row: { id: 'ULID1', entity_key: 'k', kind, at: T1 },
    });
    await writeRows(base, [ch('epss_band')], { priority: 'steady', now: NOW });
    await writeRows(base, [ch('cvss_change')], { priority: 'steady', now: NOW });
    expect((await one<{ kind: string }>(env.DB_SIGNALS, 'SELECT kind FROM changes')).kind).toBe('epss_band');
    expect(await count(env.DB_SIGNALS, 'changes')).toBe(1);
  });

  it('delete removes by primary key and leaves the rest', async () => {
    await writeRows(base, [adv('1'), adv('2')], { priority: 'steady', now: NOW });
    await writeRows(base, [{ table: 'advisories', op: 'delete', row: { source: 'nvd', source_id: '1' } }], {
      priority: 'steady',
      now: NOW,
    });
    expect(
      (await one<{ source_id: string }>(env.DB_ADVISORIES, 'SELECT source_id FROM advisories')).source_id,
    ).toBe('2');
  });

  it('a duplicate key in one call: the last row wins', async () => {
    await writeRows(base, [vuln('a', { title: 'first' }), vuln('a', { title: 'last', summary: 's' })], {
      priority: 'steady',
      now: NOW,
    });
    expect(await one(env.DB_VULNS, 'SELECT title, summary FROM vulns')).toEqual({
      title: 'last',
      summary: 's',
    });
  });

  it('refuses tables it must not write', async () => {
    await expect(
      writeRows(base, [{ table: 'budget', op: 'upsert', row: { day: 'x' } }], {
        priority: 'steady',
        now: NOW,
      }),
    ).rejects.toBeInstanceOf(RowValidationError);
    expect(await meter()).toBeUndefined();
  });
});

describe('writeRows: stored types', () => {
  it('stores booleans as integers, JSON as text, numbers as real or integer', async () => {
    await writeRows(
      base,
      [
        vuln('a', {
          ransomware: true,
          hot: false,
          sources: ['nvd', 'kev'],
          cwe: { id: 79 },
          cvss: 9,
          epss: 0.5,
          summary: null,
        }),
      ],
      { priority: 'steady', now: NOW },
    );
    const t = await one<Record<string, string>>(
      env.DB_VULNS,
      `SELECT typeof(ransomware) AS ransomware, typeof(hot) AS hot, typeof(sources) AS sources, typeof(cwe) AS cwe,
              typeof(cvss) AS cvss, typeof(epss) AS epss, typeof(summary) AS summary, typeof(title) AS title FROM vulns`,
    );
    expect(t).toEqual({
      ransomware: 'integer',
      hot: 'integer',
      sources: 'text',
      cwe: 'text',
      cvss: 'real',
      epss: 'real',
      summary: 'null',
      title: 'text',
    });
    expect(await one(env.DB_VULNS, 'SELECT ransomware, hot, sources, cwe FROM vulns')).toEqual({
      ransomware: 1,
      hot: 0,
      sources: '["nvd","kev"]',
      cwe: '{"id":79}',
    });
  });

  it('keeps defaults for columns a row does not carry', async () => {
    await writeRows(base, [vuln('a')], { priority: 'steady', now: NOW });
    expect(await one(env.DB_VULNS, 'SELECT hot, ransomware FROM vulns')).toEqual({ hot: 1, ransomware: 0 });
  });

  it('stores quotes, newlines and unicode untouched', async () => {
    const title = `it's "quoted"\nnew line é 日本語 \u{1F600}`;
    await writeRows(base, [vuln('a', { title })], { priority: 'steady', now: NOW });
    expect((await one<{ title: string }>(env.DB_VULNS, 'SELECT title FROM vulns')).title).toBe(title);
  });
});

describe('writeRows: idempotence and validation', () => {
  it('the same call twice leaves the same data', async () => {
    const rows = [
      vuln('a', { summary: 's' }),
      adv('1'),
      { table: 'advisories', op: 'delete' as const, row: { source: 'x', source_id: 'y' } },
    ];
    await writeRows(base, rows, { priority: 'steady', now: NOW });
    const snap = async () =>
      [
        await env.DB_VULNS.prepare('SELECT * FROM vulns').all(),
        await env.DB_ADVISORIES.prepare('SELECT * FROM advisories').all(),
      ].map((r) => r.results);
    const first = await snap();
    await writeRows(base, rows, { priority: 'steady', now: NOW });
    expect(await snap()).toEqual(first);
  });

  it('a validation error writes and counts nothing', async () => {
    const rows = [vuln('good'), vuln('bad', { cvss: 'high' })];
    for (const priority of ['steady', 'first-load'] as const)
      await expect(writeRows(base, rows, { priority, now: NOW })).rejects.toBeInstanceOf(RowValidationError);
    expect(await count(env.DB_VULNS, 'vulns')).toBe(0);
    expect(await meter()).toBeUndefined();
  });

  it('a missing database is named, with nothing written', async () => {
    const { ti_vulns: _omit, ...withoutVulns } = base;
    await expect(
      writeRows(withoutVulns, [adv('1'), vuln('a')], { priority: 'steady', now: NOW }),
    ).rejects.toThrow(/ti_vulns/);
    expect(await count(env.DB_ADVISORIES, 'advisories')).toBe(0);
    expect(await meter()).toBeUndefined();
  });
});

describe('writeRows: budget', () => {
  it('steady at 150,000 still writes and is counted', async () => {
    await control.prepare("INSERT INTO budget (day, d1_writes) VALUES ('2026-11-23', 150000)").run();
    const res = await writeRows(base, [adv('1'), adv('2')], { priority: 'steady', now: NOW });
    expect(res.deferred).toBe(false);
    expect(await count(env.DB_ADVISORIES, 'advisories')).toBe(2);
    expect(await meter()).toBe(150_004); // 2 rows × (1 + 1 index)
  });

  it('first-load is deferred at 89,990 with cost 20: nothing written, meter unchanged', async () => {
    await control.prepare("INSERT INTO budget (day, d1_writes) VALUES ('2026-11-23', 89990)").run();
    const rows = Array.from({ length: 10 }, (_, i) => adv(String(i)));
    const { dbs, batches } = counting();
    const res = await writeRows(dbs, rows, { priority: 'first-load', now: NOW });
    expect(res).toEqual({ written: 0, statements: 0, deferred: true });
    expect(batches).toEqual({});
    expect(await count(env.DB_ADVISORIES, 'advisories')).toBe(0);
    expect(await meter()).toBe(89_990);
  });

  it('first-load that fits is written and counted once', async () => {
    const res = await writeRows(base, [adv('1')], { priority: 'first-load', now: NOW });
    expect(res.deferred).toBe(false);
    expect(await meter()).toBe(2);
  });

  it('first-load exactly up to the cap passes', async () => {
    await control
      .prepare('INSERT INTO budget (day, d1_writes) VALUES (?1, ?2)')
      .bind('2026-11-23', FIRST_LOAD_DAILY_CAP - 2)
      .run();
    expect((await writeRows(base, [adv('1')], { priority: 'first-load', now: NOW })).deferred).toBe(false);
    expect((await writeRows(base, [adv('2')], { priority: 'first-load', now: NOW })).deferred).toBe(true);
  });

  it('a failed first-load batch (CHECK) gives its reservation back; committed batches stay', async () => {
    await reserveWrites(control, 100, 'steady', NOW);
    const rows: InboxRow[] = [
      { table: 'companies', op: 'upsert', row: { key: 'c', name: 'C' } }, // ti_world, written first
      {
        table: 'signals',
        op: 'upsert',
        row: { vuln_key: 'a', kind: 'not-a-kind', source: 's', ref: 'r', first_seen: T1 },
      },
    ];
    await expect(writeRows(base, rows, { priority: 'first-load', now: NOW })).rejects.toThrow(
      /constraint failed/i,
    );
    expect(await meter()).toBe(100);
    expect(await count(env.DB_WORLD, 'companies')).toBe(1);
    expect(await count(env.DB_SIGNALS, 'signals')).toBe(0);
  });

  it('a failed steady batch is not counted', async () => {
    const rows: InboxRow[] = [
      {
        table: 'signals',
        op: 'upsert',
        row: { vuln_key: 'a', kind: 'bad', source: 's', ref: 'r', first_seen: T1 },
      },
    ];
    await expect(writeRows(base, rows, { priority: 'steady', now: NOW })).rejects.toThrow();
    expect(await meter()).toBeUndefined();
  });
});
