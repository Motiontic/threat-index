import type { AdvisoryRecord, Affected, ParsedRecord, ParseResult } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { loadParser } from '../../parsers/src/load';
import { affectedRows, packageCost, packageWrites } from './affected';

const rec = (affected: Affected[], over: Partial<AdvisoryRecord> = {}): AdvisoryRecord => ({
  source: 'github-advisory-db',
  sourceId: 'GHSA-aaaa-bbbb-cccc',
  vulnKey: 'CVE-2026-1',
  status: 'active',
  modified: '2026-02-01T00:00:00.000Z',
  affected,
  ...over,
});
const e = (ecosystem: string, name: string, over: Partial<Affected> = {}): Affected => ({
  ecosystem,
  name,
  rangeType: 'ECOSYSTEM',
  fixed: '1.0',
  ...over,
});
const parsed = async (parser: string, dir: string, file: string) => {
  const out = (await loadParser(parser)).parse(fixture(dir, file)) as ParseResult<ParsedRecord>;
  return out.records.find((r) => 'sourceId' in r) as AdvisoryRecord;
};

describe('affectedRows', () => {
  it('keeps canonical ecosystems and release suffixes on parsed fixtures', async () => {
    const ghsa = affectedRows(await parsed('osv-ghsa', 'github-advisory-db', 'GHSA-9x82-4j54-863h.json'));
    expect(ghsa.ranges).toEqual([
      expect.objectContaining({
        ecosystem: 'npm',
        name: 'isomorphic-git',
        range_no: 0,
        vuln_key: 'CVE-2026-63476',
        range_type: 'ECOSYSTEM',
        introduced: '0',
        fixed: '1.38.6',
        last_affected: null,
        versions: null,
      }),
    ]);
    expect(ghsa.advisory).toMatchObject({ reviewed: 1, severity: 'MODERATE', status: 'active' });
    const deb = affectedRows(await parsed('osv-debian', 'debian', 'DEBIAN-CVE-2026-97845.json'));
    expect(deb.ranges.map((r) => r.ecosystem)).toEqual([
      'Debian:12',
      'Debian:13',
      'Debian:14',
      'Debian:12',
      'Debian:13',
      'Debian:14',
    ]);
    expect(deb.names).toBe(6);
    const mal = affectedRows(
      await parsed('osv-malicious', 'openssf-malicious-packages', 'MAL-2026-12884.json'),
    );
    expect(mal.ranges[0]).toMatchObject({ introduced: '0', fixed: null, last_affected: null });
    expect(mal.advisory.vuln_key).toBe('MAL-2026-12884');
  });

  it('normalises names, keeps Maven names, skips unknown ecosystems', () => {
    const p = affectedRows(
      rec([
        e('PyPI', 'Foo_Bar'),
        e('Maven', 'org.x:y'),
        e('Hackage', 'h'),
        e('Debian:12', 'bash'),
        e('npm', 'a/b'),
        e('npm', 'ok', { rangeType: undefined }),
        e('Go:zzz', 'x'),
        e('PyPI', 'v', { fixed: 'has space' }),
      ]),
    );
    expect(p.ranges.map((r) => [r.ecosystem, r.name])).toEqual([
      ['PyPI', 'foo-bar'],
      ['Maven', 'org.x:y'],
      ['Debian:12', 'bash'],
    ]);
    expect(p.skipped).toEqual({ unknown_ecosystem: 2, bad_name: 1, no_range_type: 1, bad_version: 1 });
  });

  it('numbers ranges per package and drops duplicates', () => {
    const p = affectedRows(
      rec([
        e('npm', 'a', { introduced: '1', fixed: '2' }),
        e('npm', 'b'),
        e('npm', 'a', { introduced: '3', fixed: '4' }),
        e('npm', 'a', { introduced: '1', fixed: '2' }),
      ]),
    );
    expect(p.ranges.map((r) => [r.name, r.range_no])).toEqual([
      ['a', 0],
      ['b', 0],
      ['a', 1],
    ]);
    expect(p.names).toBe(2);
  });

  it('EXACT rows carry JSON versions; a bad version rejects the row', () => {
    const ok = affectedRows(rec([{ ecosystem: 'npm', name: 'a', rangeType: 'EXACT', versions: ['1', '2'] }]));
    expect(ok.ranges[0]).toMatchObject({ range_type: 'EXACT', versions: '["1","2"]', introduced: '0' });
    const bad = affectedRows(
      rec([{ ecosystem: 'npm', name: 'a', rangeType: 'EXACT', versions: ['1', '2 3'] }]),
    );
    expect(bad.ranges).toEqual([]);
    expect(bad.skipped).toEqual({ bad_version: 1 });
  });

  it('cuts the summary to 300 characters; withdrawn records have no ranges but keep the row', () => {
    const p = affectedRows(
      rec([e('npm', 'a')], { summary: `${'x '.repeat(400)}`, severity: 'abcdefghijklmnopqrstu' }),
    );
    expect((p.advisory.summary as string).length).toBeLessThanOrEqual(300);
    expect(p.advisory.severity).toBe('abcdefghijklmnop');
    const w = affectedRows(rec([e('npm', 'a')], { status: 'withdrawn' }));
    expect(w.ranges).toEqual([]);
    expect(w.names).toBe(1);
    expect(w.advisory.status).toBe('withdrawn');
  });

  it('gives no rows for an unsafe id', () => {
    const p = affectedRows(rec([e('npm', 'a')], { sourceId: '../x' }));
    expect(p.names).toBe(0);
    expect(packageWrites(rec([]), p, { ranges: [] })).toEqual([]);
  });
});

describe('packageWrites', () => {
  const r1 = rec([e('npm', 'a'), e('npm', 'b')]);
  const first = () => packageWrites(r1, affectedRows(r1), { ranges: [] });
  const stored = (rows: ReturnType<typeof first>) => ({
    advisory: rows.find((x) => x.table === 'package_advisories')?.row,
    ranges: rows.filter((x) => x.table === 'affected').map((x) => x.row),
  });

  it('writes upserts then the advisory row', () => {
    const rows = first();
    expect(rows.map((x) => `${x.table}:${x.op}`)).toEqual([
      'affected:upsert',
      'affected:upsert',
      'package_advisories:upsert',
    ]);
    expect(packageCost(rows)).toBe(3 + 3 + 2);
  });

  it('writes nothing when the stored row is the same or newer', () => {
    const s = stored(first());
    expect(packageWrites(r1, affectedRows(r1), s)).toEqual([]);
    const older = rec(r1.affected ?? [], { modified: '2026-01-01T00:00:00.000Z' });
    expect(packageWrites(older, affectedRows(older), s)).toEqual([]);
  });

  it('a newer version without one package deletes exactly that package', () => {
    const s = stored(first());
    const next = rec([e('npm', 'a')], { modified: '2026-03-01T00:00:00.000Z' });
    const rows = packageWrites(next, affectedRows(next), s);
    expect(rows.map((x) => `${x.table}:${x.op}`)).toEqual([
      'affected:upsert',
      'affected:delete',
      'package_advisories:upsert',
    ]);
    expect(rows[1]?.row).toEqual({
      ecosystem: 'npm',
      name: 'b',
      source: 'github-advisory-db',
      source_id: 'GHSA-aaaa-bbbb-cccc',
      range_no: 0,
    });
    expect(packageCost(rows)).toBe(3 + 3 + 2);
  });

  it('a withdrawn version deletes every stored range and writes the status', () => {
    const s = stored(first());
    const w = rec([e('npm', 'a'), e('npm', 'b')], {
      status: 'withdrawn',
      modified: '2026-03-01T00:00:00.000Z',
    });
    const rows = packageWrites(w, affectedRows(w), s);
    expect(rows.filter((x) => x.op === 'delete')).toHaveLength(2);
    expect(rows.at(-1)?.row).toMatchObject({ status: 'withdrawn' });
    expect(rows.some((x) => x.table === 'affected' && x.op === 'upsert')).toBe(false);
  });

  it('no packages and no stored row gives nothing', () => {
    const none = rec([e('Hackage', 'x')]);
    expect(packageWrites(none, affectedRows(none), { ranges: [] })).toEqual([]);
  });
});
