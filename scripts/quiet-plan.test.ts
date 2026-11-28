import { describe, expect, it } from 'vitest';
import {
  exploitDatesSql,
  firstLoadBoundaries,
  fixDatesSql,
  keyBatches,
  neededKeys,
  planQuiet,
  updateChunks,
  withRetry,
} from './lib/quiet-plan.mjs';

const AT = '2026-11-25T12:00:00.000Z';
type C = {
  id: string;
  kind: string;
  source: string | null;
  entity_key: string;
  new: string | null;
  at: string;
  event_at?: string | null;
  quiet?: string | null;
};
const row = (id: string, kind: string, source: string | null, over: Partial<C> = {}): C => ({
  id,
  kind,
  source,
  entity_key: `CVE-${id}`,
  new: null,
  at: AT,
  ...over,
});
const maps = (over: Record<string, unknown> = {}) => ({
  exploit: new Map<string, string>(),
  fix: new Map<string, string>(),
  notice: new Map<string, string>(),
  boundaries: new Map(),
  ...over,
});
const byId = (u: { id: string }[]) => Object.fromEntries(u.map((x) => [x.id, x]));

describe('planQuiet: one fixture row per kind and reason', () => {
  const changes = [
    row('x1', 'public_exploit', 'exploit-db'), // 2014 exploit
    row('x2', 'public_exploit', 'metasploit'), // exploit from yesterday
    row('k1', 'newly_exploited', 'cisa-kev', { new: '2021-12-01' }),
    row('k2', 'newly_exploited', 'cisa-kev', { new: '2026-11-24' }),
    row('f1', 'fix_released', 'github-advisory-db'),
    row('f2', 'fix_released', 'msrc'),
    row('f3', 'fix_released', 'debian'), // no advisory date known
    row('b1', 'breach_notice', 'wa-ag', { new: 'wa-ag:1' }),
    row('b2', 'breach_notice', 'hibp', { new: 'hibp:1' }), // no notified or discovered
    row('e1', 'epss_band', 'epss'),
    row('n1', 'new_advisory', 'osv'),
    row('c1', 'cvss_change', 'nvd'),
  ];
  const ctx = maps({
    exploit: new Map([
      ['CVE-x1', '2014-03-01'],
      ['CVE-x2', '2026-11-24'],
    ]),
    fix: new Map([
      ['github-advisory-db\u0000CVE-f1', '2022-01-01'],
      ['msrc\u0000CVE-f2', '2026-11-20'],
    ]),
    notice: new Map([['wa-ag:1', '2023-05-05']]),
  });

  it('marks old rows, leaves current ones, and gives missing dates the benefit of the doubt', () => {
    const { updates } = planQuiet(changes, ctx);
    const u = byId(updates);
    expect(u.x1).toEqual({ id: 'x1', event_at: '2014-03-01', quiet: 'old' });
    expect(u.k1).toMatchObject({ quiet: 'old', event_at: '2021-12-01' });
    expect(u.f1).toMatchObject({ quiet: 'old' });
    expect(u.b1).toMatchObject({ quiet: 'old', event_at: '2023-05-05' });
    // Current: event_at is recorded, the row still alerts.
    expect(u.x2).toEqual({ id: 'x2', event_at: '2026-11-24', quiet: null });
    expect(u.k2).toEqual({ id: 'k2', event_at: '2026-11-24', quiet: null });
    expect(u.f2).toEqual({ id: 'f2', event_at: '2026-11-20', quiet: null });
    // No date, or no rule: no update at all.
    for (const id of ['f3', 'b2', 'e1', 'n1', 'c1']) expect(u[id]).toBeUndefined();
  });

  it('first-load rows: until the first completed run, all for a never-completed source, none without runs', () => {
    const boundaries = firstLoadBoundaries(
      [
        { source_id: 'nuclei', status: 'ok', finished_at: '2026-11-25T12:30:00Z', error: null },
        { source_id: 'nuclei', status: 'ok', finished_at: '2026-11-26T12:30:00Z', error: null },
        { source_id: 'hibp', status: 'failed', finished_at: '2026-11-25T01:00:00Z', error: 'x' },
        {
          source_id: 'debian',
          status: 'ok',
          finished_at: '2026-11-24T00:00:00Z',
          error: 'step limit reached after 21 steps',
        },
      ],
      [{ source_id: 'msrc', kind: 'first-load', status: 'complete', finished_at: '2026-11-25T13:00:00Z' }],
    );
    expect(boundaries.get('nuclei')).toEqual({ until: '2026-11-25T12:30:00Z' });
    expect(boundaries.get('hibp')).toEqual({ all: true });
    expect(boundaries.get('debian')).toEqual({ all: true }); // only a step-limit run
    expect(boundaries.get('msrc')).toEqual({ until: '2026-11-25T13:00:00Z' });
    expect(boundaries.has('cisa-vulnrichment')).toBe(false);

    const rows = [
      row('e1', 'public_exploit', 'nuclei'), // at 12:00, before the run ended
      row('e2', 'public_exploit', 'nuclei', { at: '2026-11-25T13:00:00Z' }), // after it: alerts
      row('h1', 'breach_notice', 'hibp', { new: 'hibp:1' }),
      row('m1', 'fix_released', 'msrc'),
      row('v1', 'newly_exploited', 'cisa-vulnrichment', { new: '2026-11-24' }),
      row('o1', 'newly_exploited', 'nuclei', { new: '2015-01-01' }), // old wins over first_load
    ];
    const u = byId(planQuiet(rows, maps({ boundaries })).updates);
    expect(u.e1).toMatchObject({ quiet: 'first_load' });
    expect(u.e2).toBeUndefined();
    expect(u.h1).toMatchObject({ quiet: 'first_load' });
    expect(u.m1).toMatchObject({ quiet: 'first_load' });
    expect(u.v1).toEqual({ id: 'v1', event_at: '2026-11-24', quiet: null });
    expect(u.o1).toMatchObject({ quiet: 'old' });
  });

  it('never marks epss_band first_load, and ignores skipped runs', () => {
    const boundaries = firstLoadBoundaries(
      [
        // epss runs only hand off to the epss-diff job, so none completes a pass
        { source_id: 'epss', status: 'heavy', finished_at: '2026-11-25T00:00:05Z', error: null },
        // a source read from another source's records: only skipped runs
        {
          source_id: 'cisa-vulnrichment',
          status: 'skipped',
          finished_at: '2026-11-25T00:00:00Z',
          error: 'x',
        },
      ],
      [{ source_id: 'epss', kind: 'epss-diff', status: 'complete', finished_at: '2026-11-25T00:10:00Z' }],
    );
    expect(boundaries.get('epss')).toEqual({ all: true });
    expect(boundaries.has('cisa-vulnrichment')).toBe(false);
    const rows = [
      row('p1', 'epss_band', 'epss', { new: '0.2' }),
      row('c1', 'cvss_change', 'cisa-vulnrichment'),
    ];
    expect(planQuiet(rows, maps({ boundaries })).updates).toEqual([]);
  });

  it('never touches a row that is already quiet, and never plans `held`', () => {
    const rows = [
      row('q1', 'public_exploit', 'exploit-db', { quiet: 'held' }),
      row('q2', 'newly_exploited', 'cisa-kev', { new: '2001-01-01', quiet: 'first_load' }),
    ];
    const { updates } = planQuiet(rows, maps({ exploit: new Map([['CVE-q1', '2001-01-01']]) }));
    expect(updates).toEqual([]);
    const all = planQuiet(changes, ctx).updates;
    expect(all.some((x) => x.quiet === 'held')).toBe(false);
  });

  it('running it twice changes nothing', () => {
    const first = planQuiet(changes, ctx);
    const applied = changes.map((c) => ({ ...c, ...(byId(first.updates)[c.id] ?? {}) }));
    expect(planQuiet(applied, ctx).updates).toEqual([]);
  });

  it('summarises by kind, source and reason', () => {
    const { summary } = planQuiet(changes, ctx);
    expect(summary).toContainEqual({ kind: 'public_exploit', source: 'exploit-db', reason: 'old', rows: 1 });
    expect(summary.reduce((n, s) => n + s.rows, 0)).toBe(4);
  });
});

describe('updateChunks', () => {
  it('writes guarded UPDATEs, escapes quotes, and splits into chunks', () => {
    const updates = Array.from({ length: 5 }, (_, i) => ({
      id: `a'${i}`,
      event_at: '2020-01-01',
      quiet: 'old',
    }));
    const chunks = updateChunks(updates, 2);
    expect(chunks).toHaveLength(3);
    expect(chunks[0]).toContain("WHERE id = 'a''0' AND quiet IS NULL;");
    expect(chunks[0]).toContain("SET event_at = '2020-01-01', quiet = 'old'");
    expect(updateChunks([{ id: 'z', event_at: null, quiet: null }])[0]).toContain(
      'event_at = NULL, quiet = NULL',
    );
  });
  it('refuses to write held', () => {
    expect(() => updateChunks([{ id: 'z', event_at: null, quiet: 'held' }])).toThrow(/held/);
  });
});

describe('reading dates by key', () => {
  it('neededKeys picks only public_exploit and fix_released entity keys, once each', () => {
    const k = neededKeys([
      row('a', 'public_exploit', 's', { entity_key: 'CVE-1' }),
      row('b', 'public_exploit', 's2', { entity_key: 'CVE-1' }),
      row('c', 'fix_released', 's', { entity_key: 'CVE-2' }),
      row('d', 'fix_released', 's3', { entity_key: 'CVE-2' }),
      row('e', 'newly_exploited', 's', { entity_key: 'CVE-3' }),
      row('f', 'new_advisory', 's', { entity_key: 'CVE-4' }),
    ]);
    expect([...k.exploit]).toEqual(['CVE-1']);
    expect([...k.fix]).toEqual(['CVE-2']);
  });

  it('keyBatches splits 1,801 keys into 800/800/201, sorted', () => {
    const keys = Array.from({ length: 1801 }, (_, i) => `K${String(i).padStart(5, '0')}`).reverse();
    const b = keyBatches(new Set(keys));
    expect(b.map((x: string[]) => x.length)).toEqual([800, 800, 201]);
    expect(b.flat()).toEqual([...keys].sort());
  });

  it('SQL builders quote with doubled single quotes and group by key', () => {
    const e = exploitDatesSql(["a'b", 'c']);
    expect(e).toContain("IN ('a''b', 'c')");
    expect(e).toContain("kind = 'public_exploit'");
    expect(e).toContain('GROUP BY vuln_key');
    const f = fixDatesSql(["a'b"]);
    expect(f).toContain("IN ('a''b')");
    expect(f).toContain('GROUP BY source, vuln_key');
  });

  it('a plan from by-key maps equals the plan from the full maps', () => {
    const changes = [
      row('x1', 'public_exploit', 'exploit-db'),
      row('x2', 'public_exploit', 'metasploit'),
      row('f1', 'fix_released', 'msrc'),
      row('f2', 'fix_released', 'github-advisory-db'),
    ];
    const fullExploit = new Map([
      ['CVE-x1', '2014-01-01'],
      ['CVE-x2', '2026-11-24'],
      ['CVE-unrelated', '2010-01-01'],
    ]);
    const fullFix = new Map([
      ['msrc\u0000CVE-f1', '2020-01-01'],
      ['github-advisory-db\u0000CVE-f2', '2026-11-24'],
      ['msrc\u0000CVE-unrelated', '2010-01-01'],
    ]);
    const need = neededKeys(changes);
    const byKey = <T>(m: Map<string, T>, keep: (k: string) => boolean) =>
      new Map([...m].filter(([k]) => keep(k)));
    const keyed = maps({
      exploit: byKey(fullExploit, (k) => need.exploit.has(k)),
      fix: byKey(fullFix, (k) => need.fix.has(k.split('\u0000')[1])),
    });
    expect(keyed.exploit.size).toBe(2);
    expect(planQuiet(changes, keyed)).toEqual(
      planQuiet(changes, maps({ exploit: fullExploit, fix: fullFix })),
    );
  });
});

describe('withRetry', () => {
  const overload = () => new Error('D1 DB is overloaded. Too many resources [code: 7429]');
  it('retries overloads with 5 s x attempt waits, then returns', async () => {
    let n = 0;
    const waits: number[] = [];
    const out = await withRetry(
      async () => {
        if (++n <= 2) throw overload();
        return 'done';
      },
      { sleep: async (ms: number) => void waits.push(ms) },
    );
    expect(out).toBe('done');
    expect(n).toBe(3);
    expect(waits).toEqual([5000, 10000]);
  });

  it('recognises an overload in the captured stderr', async () => {
    let n = 0;
    const out = await withRetry(
      async () => {
        if (++n === 1) throw Object.assign(new Error('Command failed'), { stderr: 'ERROR code: 7429' });
        return 1;
      },
      { sleep: async () => {} },
    );
    expect(out).toBe(1);
  });

  it('throws any other error at once', async () => {
    let n = 0;
    await expect(
      withRetry(
        async () => {
          n++;
          throw new Error('no such table');
        },
        { sleep: async () => {} },
      ),
    ).rejects.toThrow('no such table');
    expect(n).toBe(1);
  });

  it('gives up after 5 retries', async () => {
    let n = 0;
    await expect(
      withRetry(
        async () => {
          n++;
          throw overload();
        },
        { sleep: async () => {} },
      ),
    ).rejects.toThrow(/7429/);
    expect(n).toBe(6);
  });
});
