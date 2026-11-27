import { describe, expect, it } from 'vitest';
import { firstLoadBoundaries, planQuiet, updateChunks } from './lib/quiet-plan.mjs';

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
        { source_id: 'epss', status: 'ok', finished_at: '2026-11-25T12:30:00Z', error: null },
        { source_id: 'epss', status: 'ok', finished_at: '2026-11-26T12:30:00Z', error: null },
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
    expect(boundaries.get('epss')).toEqual({ until: '2026-11-25T12:30:00Z' });
    expect(boundaries.get('hibp')).toEqual({ all: true });
    expect(boundaries.get('debian')).toEqual({ all: true }); // only a step-limit run
    expect(boundaries.get('msrc')).toEqual({ until: '2026-11-25T13:00:00Z' });
    expect(boundaries.has('cisa-vulnrichment')).toBe(false);

    const rows = [
      row('e1', 'epss_band', 'epss'), // at 12:00, before the run ended
      row('e2', 'epss_band', 'epss', { at: '2026-11-25T13:00:00Z' }), // after it: alerts
      row('h1', 'breach_notice', 'hibp', { new: 'hibp:1' }),
      row('m1', 'fix_released', 'msrc'),
      row('v1', 'newly_exploited', 'cisa-vulnrichment', { new: '2026-11-24' }),
      row('o1', 'newly_exploited', 'epss', { new: '2015-01-01' }), // old wins over first_load
    ];
    const u = byId(planQuiet(rows, maps({ boundaries })).updates);
    expect(u.e1).toMatchObject({ quiet: 'first_load' });
    expect(u.e2).toBeUndefined();
    expect(u.h1).toMatchObject({ quiet: 'first_load' });
    expect(u.m1).toMatchObject({ quiet: 'first_load' });
    expect(u.v1).toEqual({ id: 'v1', event_at: '2026-11-24', quiet: null });
    expect(u.o1).toMatchObject({ quiet: 'old' });
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
