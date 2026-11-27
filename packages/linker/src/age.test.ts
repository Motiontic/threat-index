import type { AdvisoryRecord, NoticeRecord, SignalRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { ageQuiet, firstLoadQuiet, holdOver, MAX_ALERTS_PER_RUN } from './age';
import { link } from './link';
import { KEV_EXPLOITED, makeFake, NOW, vulnRow } from './testing/fake-deps';

const CVE = 'CVE-2025-3248';
const AT = NOW.toISOString(); // 2026-03-01
const daysBefore = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString().slice(0, 10);

type Out = Awaited<ReturnType<typeof link>>;
const changes = (out: Out) => out.rows.filter((r) => r.table === 'changes').map((r) => r.row);

describe('ageQuiet', () => {
  it('30 days old is old; 14 and 13 days still alert', () => {
    expect(ageQuiet(daysBefore(30), AT)).toBe('old');
    expect(ageQuiet(daysBefore(15), AT)).toBe('old');
    expect(ageQuiet(daysBefore(14), AT)).toBeNull();
    expect(ageQuiet(daysBefore(13), AT)).toBeNull();
  });
  it('compares days, not hours', () => {
    expect(ageQuiet('2026-02-15T23:59:00Z', AT)).toBeNull(); // 14 days by day
    expect(ageQuiet('2026-02-14T23:59:00Z', AT)).toBe('old');
  });
  it('a missing, unparseable or future date alerts', () => {
    expect(ageQuiet(null, AT)).toBeNull();
    expect(ageQuiet(undefined, AT)).toBeNull();
    expect(ageQuiet('not a date', AT)).toBeNull();
    expect(ageQuiet('2030-01-01', AT)).toBeNull();
  });
});

describe('quiet helpers', () => {
  it('firstLoadQuiet keeps an existing reason', () => {
    const rows = [{ quiet: null }, { quiet: 'old' }, {}];
    expect(firstLoadQuiet(rows)).toBe(2);
    expect(rows.map((r) => r.quiet)).toEqual(['first_load', 'old', 'first_load']);
  });
  it('holdOver keeps the first rows up to the limit and skips already quiet rows', () => {
    const rows = [{ quiet: 'old' }, ...Array.from({ length: 5 }, () => ({ quiet: null as string | null }))];
    expect(holdOver(rows, 1, 4)).toEqual({ alerts: 3, held: 2 });
    expect(rows.map((r) => r.quiet)).toEqual(['old', null, null, null, 'held', 'held']);
    expect(holdOver([{ quiet: null }], 5000)).toEqual({ alerts: 0, held: 1 });
    expect(MAX_ALERTS_PER_RUN).toBe(2000);
  });
});

describe('the linker sets event_at and quiet', () => {
  it('newly_exploited: the KEV date', async () => {
    const f = makeFake();
    f.put('vulns', vulnRow(CVE));
    const old = await link([KEV_EXPLOITED], f.deps);
    expect(changes(old)).toMatchObject([{ kind: 'newly_exploited', event_at: '2025-05-05', quiet: 'old' }]);
    const f2 = makeFake();
    f2.put('vulns', vulnRow(CVE));
    const fresh = await link([{ ...KEV_EXPLOITED, firstSeen: daysBefore(14) } as SignalRecord], f2.deps);
    expect(changes(fresh)).toMatchObject([{ event_at: daysBefore(14), quiet: null }]);
  });

  it('public_exploit: the earliest firstSeen in the batch, so an old and a new signal give old', async () => {
    const f = makeFake();
    f.put('vulns', vulnRow(CVE));
    const sig = (source: string, ref: string, firstSeen: string): SignalRecord => ({
      vulnKey: CVE,
      kind: 'public_exploit',
      source,
      ref,
      firstSeen,
    });
    const out = await link(
      [sig('metasploit', 'm/1', daysBefore(0)), sig('exploit-db', 'EDB-1', '2014-01-02')],
      f.deps,
    );
    expect(changes(out)).toMatchObject([{ kind: 'public_exploit', event_at: '2014-01-02', quiet: 'old' }]);
  });

  it('fix_released: the published date of the advisory that set fixSource, else its modified', async () => {
    const fix = [{ ecosystem: 'npm', name: 'x', fixed: '1.2.3' }];
    const adv = (over: Partial<AdvisoryRecord>): AdvisoryRecord => ({
      source: 'github-advisory-db',
      sourceId: 'GHSA-cfgh-jmpq-rvwx',
      vulnKey: CVE,
      status: 'active',
      modified: daysBefore(1),
      affected: fix,
      ...over,
    });
    const f = makeFake();
    f.put('vulns', vulnRow(CVE));
    const a = await link([adv({ published: '2020-01-01' })], f.deps);
    expect(changes(a).find((c) => c.kind === 'fix_released')).toMatchObject({
      event_at: '2020-01-01',
      quiet: 'old',
    });
    const f2 = makeFake();
    f2.put('vulns', vulnRow(CVE));
    const b = await link([adv({ modified: daysBefore(2) })], f2.deps);
    expect(changes(b).find((c) => c.kind === 'fix_released')).toMatchObject({
      event_at: daysBefore(2),
      quiet: null,
    });
  });

  it('breach_notice: notified, else discovered; never occurredFrom', async () => {
    const base: NoticeRecord = {
      source: 'ca-ag',
      noticeId: 'ca1',
      rawName: 'Acme Corp',
      companyKey: 'cik:1234',
      occurredFrom: '2019-01-01',
      occurredTo: '2019-02-01',
      notified: daysBefore(3),
      countUnit: 'state_residents',
    };
    const a = await link([base], makeFake().deps);
    expect(changes(a)).toMatchObject([{ kind: 'breach_notice', event_at: daysBefore(3), quiet: null }]);
    const b = await link(
      [{ ...base, noticeId: 'ca2', notified: undefined, discovered: '2020-05-05' }],
      makeFake().deps,
    );
    expect(changes(b)).toMatchObject([{ event_at: '2020-05-05', quiet: 'old' }]);
    const c = await link(
      [{ ...base, noticeId: 'ca3', notified: undefined, discovered: undefined }],
      makeFake().deps,
    );
    expect(changes(c)).toMatchObject([{ event_at: null, quiet: null }]);
  });

  it('cvss_change: no event date, never quiet', async () => {
    const f = makeFake();
    f.put('vulns', vulnRow(CVE, { cvss: 5 }));
    const out = await link(
      [
        {
          key: CVE,
          kind: 'cve',
          title: 'T',
          published: '2020-01-01',
          modified: '2020-01-02T00:00:00Z',
          cwe: [],
          aliases: [],
          source: 'cve-list',
          cvss: 8,
          cvssSource: 'nvd',
        } as never,
      ],
      f.deps,
    );
    const c = changes(out).filter((r) => r.kind === 'cvss_change');
    expect(c).toHaveLength(1);
    for (const r of c) expect(r).toMatchObject({ event_at: null, quiet: null });
  });
});
