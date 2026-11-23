import type { NoticeRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch as feedFetch } from '../../patterns/src/feed';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { parseCaAg } from '../src/ca-ag';
import { parseHhsOcr } from '../src/hhs-ocr';
import { loadParser } from '../src/load';
import { cleanName, isoDay, noticeKey, toCount, usDate } from '../src/notice-us';
import { parseSecEdgar } from '../src/sec-edgar';
import { parseWaAg } from '../src/wa-ag';

const json = (source: string, file: string) => JSON.parse(fixture(source, file)) as Record<string, unknown>[];
const secEntries = async () => {
  const source = SOURCE_BY_ID.get('sec-edgar');
  if (!source?.pull?.feed) throw new Error('sec-edgar has no feed pull');
  const h = makeCtx({
    source,
    routes: [
      route(
        source.pull.feed.url,
        reply(fixture('sec-edgar', 'current-8k.atom'), 200, { 'content-type': 'application/atom+xml' }),
      ),
    ],
  });
  return (await feedFetch(h.ctx)).items.map((i) => i.body);
};

describe('notice-us helpers', () => {
  it('usDate: real calendar dates only', () => {
    expect(usDate('10/16/2026')).toBe('2026-10-16');
    expect(usDate('1/2/2026')).toBe('2026-01-02');
    expect(usDate('02/29/2028')).toBe('2028-02-29');
    expect(usDate('02/29/2026')).toBeUndefined();
    expect(usDate('02/29/1900')).toBeUndefined();
    expect(usDate('02/29/2000')).toBe('2000-02-29');
    expect(usDate('02/30/2026')).toBeUndefined();
    expect(usDate('13/01/2026')).toBeUndefined();
    expect(usDate('n/a')).toBeUndefined();
    expect(usDate(undefined)).toBeUndefined();
  });
  it('isoDay: leading real date', () => {
    expect(isoDay('2026-11-14T00:00:00.000')).toBe('2026-11-14');
    expect(isoDay('2026-02-29T00:00:00.000')).toBeUndefined();
    expect(isoDay('2028-02-29')).toBe('2028-02-29');
    expect(isoDay('x2026-11-14')).toBeUndefined();
    expect(isoDay(5)).toBeUndefined();
  });
  it('toCount: safe non-negative integers and thousands commas only', () => {
    expect(toCount('1351650')).toBe(1351650);
    expect(toCount('1,200')).toBe(1200);
    expect(toCount('0')).toBe(0);
    for (const bad of [
      '1e3',
      '-5',
      '12.5',
      'n/a',
      '10-49',
      '1,20',
      '',
      '99999999999',
      '9007199254740993',
      ' ',
      undefined,
      null,
      {},
    ])
      expect(toCount(bad), String(bad)).toBeUndefined();
  });
  it('cleanName and noticeKey', () => {
    expect(cleanName('  A \n\t B\u0000C  ')).toBe('A B C');
    expect(cleanName('   ')).toBeUndefined();
    expect(cleanName('x'.repeat(300))?.length).toBe(200);
    expect(noticeKey('2026-10-16', 'OH', 'Central Ohio (COPC)')).toBe('2026-10-16:oh:central-ohio-copc-');
    expect(noticeKey('x'.repeat(300)).length).toBe(200);
  });
});

describe('sec-edgar', () => {
  it('only the Item 1.05 entries give records; the CIK mismatch is skipped', async () => {
    const out = parseSecEdgar(await secEntries());
    expect(out.records).toEqual([
      {
        source: 'sec-edgar',
        noticeId: '0001104659-26-115541',
        rawName: 'Park Dental Partners, Inc.',
        companyKey: 'cik:0002069604',
        notified: '2026-10-13',
        countUnit: 'not_stated',
        jurisdiction: 'US',
        url: 'https://www.sec.gov/Archives/edgar/data/2069604/000110465926115541/0001104659-26-115541-index.htm',
      },
    ]);
    expect(out.skipped).toBe(1);
    expect(out.unknownFields).toEqual([]);
  });
  it('unknown entry keys are reported; non-8-K forms give nothing', () => {
    const out = parseSecEdgar({
      title: '10-K - Foo Inc (0000000001) (Filer)',
      summary: 'Item 1.05',
      category: { '@_term': '10-K' },
      extra: 1,
    });
    expect(out).toEqual({ records: [], unknownFields: ['extra'], skipped: 0 });
  });
  it('falls back to the id URN, the title form and the updated date', () => {
    const out = parseSecEdgar({
      title: '8-K - Foo Inc (0000000001) (Filer)',
      link: { '@_href': 'https://www.sec.gov/Archives/edgar/data/1/x/y-index.htm' },
      summary: 'Item 1.05: Material',
      updated: '2026-11-01T10:00:00-04:00',
      id: 'urn:tag:sec.gov,2008:accession-number=0000000001-26-000001',
    });
    expect(out.records[0]).toMatchObject({
      noticeId: '0000000001-26-000001',
      notified: '2026-11-01',
      companyKey: 'cik:0000000001',
    });
  });
  it('bad accession is skipped', () => {
    const out = parseSecEdgar({
      title: '8-K - Foo Inc (0000000001) (Filer)',
      link: { '@_href': 'https://www.sec.gov/Archives/edgar/data/1/x/y-index.htm' },
      summary: 'Item 1.05',
      id: 'urn:tag:sec.gov,2008:accession-number=nope',
    });
    expect(out).toMatchObject({ records: [], skipped: 1 });
  });
});

describe('hhs-ocr', () => {
  const rows = json('hhs-ocr', 'rows.json');
  const out = parseHhsOcr(rows);
  it('individuals, not_stated, bad date skipped, unknown key reported', () => {
    expect(out.records.map((r) => [r.noticeId, r.count, r.countUnit])).toEqual([
      ['2026-10-16:oh:central-ohio-primary-care-physicians-inc-copc-', 1351650, 'individuals'],
      ['2026-10-16:vt:rose-poney-lcmhc-restoration-counseling-llc', 662, 'individuals'],
      ['2026-10-15:nc:lisa-jo-adornetto-dds-pa', 2000, 'individuals'],
      ['2026-10-14:tx:example-dental-group-llc', undefined, 'not_stated'],
      ['2026-10-13:fl:unknown-key-clinic', 750, 'individuals'],
    ]);
    expect(out.skipped).toBe(1);
    expect(out.unknownFields).toEqual(['surprise']);
    expect(out.records[0]).toMatchObject({
      source: 'hhs-ocr',
      notified: '2026-10-16',
      jurisdiction: 'US',
      dataTypes: ['health'],
      url: 'https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf',
    });
    expect('count' in (out.records[3] as NoticeRecord)).toBe(false);
  });
});

describe('ca-ag', () => {
  const out = parseCaAg(json('ca-ag', 'rows.json'));
  it('ids, date ranges, n/a, and a foreign link skipped', () => {
    expect(out.records.map((r) => [r.noticeId, r.occurredFrom, r.occurredTo, r.notified])).toEqual([
      ['sb24-633250', '2026-06-03', '2026-06-03', '2026-11-20'],
      ['sb24-633182', '2026-06-24', '2026-06-24', '2026-11-20'],
      ['sb24-633174', '2025-04-26', '2025-04-26', '2026-11-20'],
      ['sb24-633059', undefined, undefined, '2026-11-17'],
      ['sb24-632903', '2026-03-25', '2026-07-13', '2026-11-13'],
    ]);
    expect(out.skipped).toBe(1);
    expect(out.unknownFields).toEqual([]);
    expect(out.records[0]).toMatchObject({
      countUnit: 'not_stated',
      jurisdiction: 'US-CA',
      url: 'https://oag.ca.gov/ecrime/databreach/reports/sb24-633250',
    });
    expect('occurredFrom' in (out.records[3] as NoticeRecord)).toBe(false);
  });
});

describe('wa-ag', () => {
  const out = parseWaAg(json('wa-ag', 'sb4j-ca4h.sample.json'));
  it('state_residents, comma counts, missing count, bad id skipped', () => {
    expect(out.records.map((r) => [r.noticeId, r.count, r.countUnit])).toEqual([
      ['26286', 16307, 'state_residents'],
      ['26285', 1093, 'state_residents'],
      ['26284', out.records[2]?.count, out.records[2]?.countUnit],
      ['90001', undefined, 'not_stated'],
      ['90002', 1200, 'state_residents'],
      ['90003', 40, 'state_residents'],
    ]);
    expect(out.skipped).toBe(1);
    expect(out.unknownFields).toEqual(['surprise']);
  });
  it('maps the dates and url; a range is never a count; an impossible date is dropped', () => {
    expect(out.records[0]).toEqual({
      source: 'wa-ag',
      noticeId: '26286',
      rawName: 'Prism Medical Products, LLC',
      occurredFrom: '2026-10-18',
      occurredTo: '2026-10-19',
      discovered: '2026-10-19',
      notified: '2026-11-14',
      count: 16307,
      countUnit: 'state_residents',
      jurisdiction: 'US-WA',
      url: 'https://data.wa.gov/resource/sb4j-ca4h.json?id=26286',
    });
    const noCount = out.records.find((r) => r.noticeId === '90001');
    expect(noCount && 'count' in noCount).toBe(false);
    const leap = out.records.find((r) => r.noticeId === '90002');
    expect(leap?.occurredFrom).toBeUndefined();
    expect(leap?.occurredTo).toBe('2026-03-01');
  });
});

describe('all four', () => {
  const run = async () => ({
    sec: parseSecEdgar(await secEntries()).records,
    hhs: parseHhsOcr(json('hhs-ocr', 'rows.json')).records,
    ca: parseCaAg(json('ca-ag', 'rows.json')).records,
    wa: parseWaAg(json('wa-ag', 'sb4j-ca4h.sample.json')).records,
  });
  it('never a count with not_stated; same input twice gives identical noticeIds', async () => {
    const a = await run();
    const b = await run();
    const all = Object.values(a).flat();
    for (const r of all) if (r.countUnit === 'not_stated') expect('count' in r, r.noticeId).toBe(false);
    for (const r of all) if ('count' in r) expect(r.countUnit).not.toBe('not_stated');
    expect(
      Object.values(b)
        .flat()
        .map((r) => r.noticeId),
    ).toEqual(all.map((r) => r.noticeId));
    expect(new Set(all.map((r) => `${r.source}|${r.noticeId}`)).size).toBe(all.length);
  });
  it('no record holds Web Description text or item titles', async () => {
    const text = JSON.stringify(Object.values(await run()).flat());
    expect(text).not.toMatch(/Material Cybersecurity Incidents|Other Events|Financial Statements/);
    const listing = fixture('hhs-ocr', 'listing.html');
    expect(listing).toContain('Web Description');
    for (const r of Object.values(await run()).flat()) expect(Object.keys(r)).not.toContain('description');
  });
  it('wrong input types throw', () => {
    for (const p of [parseSecEdgar, parseHhsOcr, parseCaAg, parseWaAg]) {
      expect(() => p('x')).toThrow();
      expect(() => p(null)).toThrow();
      expect(() => p([1])).toThrow();
    }
  });
  it('loadParser resolves the four parsers', async () => {
    for (const n of ['sec-edgar', 'hhs-ocr', 'ca-ag', 'wa-ag'])
      expect(typeof (await loadParser(n)).parse).toBe('function');
  });
});
