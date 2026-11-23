import type { AdvisoryRecord, IncidentRecord, NoticeRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { parseFeed, sanitizeLinks } from '../../patterns/src/feed';
import { advisoryId, MAX_CVES_PER_ADVISORY, parseCisaAdvisory } from '../src/cisa-advisories';
import { MAX_DATA_TYPES, parseHibp } from '../src/hibp';
import { loadParser } from '../src/load';
import { MAX_TITLE, parseVcdb } from '../src/vcdb';

const feedItems = (file: string) => parseFeed(fixture('cisa-advisories', file)).map((i) => sanitizeLinks(i));

describe('hibp', () => {
  const entries = JSON.parse(fixture('hibp', 'breaches.json')) as Array<Record<string, unknown>>;
  const byName = (n: string) => entries.find((e) => e.Name === n) as Record<string, unknown>;

  it('keeps exactly Adobe, Bromcom and AllegedATT', () => {
    const notices: NoticeRecord[] = [];
    for (const e of entries) notices.push(...parseHibp(e).records);
    expect(notices.map((n) => n.noticeId)).toEqual(['Adobe', 'Bromcom', 'AllegedATT']);
    for (const n of notices) {
      const e = byName(n.noticeId);
      expect(n.source).toBe('hibp');
      expect(n.countUnit).toBe('accounts');
      expect(n.count).toBe(e.PwnCount);
      expect(n.occurredFrom).toBe(e.BreachDate);
      expect(n.url).toBe(`https://haveibeenpwned.com/Breach/${n.noticeId}`);
      expect(n.dataTypes).toEqual([...new Set(e.DataClasses as string[])]);
      expect(n.companyKey).toBeUndefined();
      expect(n.notified).toBeUndefined();
      expect(n.discovered).toBeUndefined();
    }
    expect(notices[0]).toMatchObject({ rawName: 'Adobe', count: 152445165, occurredFrom: '2013-10-04' });
  });

  it('skips sensitive, spam, fabricated, unverified and stealer-log entries', () => {
    for (const n of ['AdultFriendFinder', 'Acuity', 'JustDate', '126', 'AlienStealerLogs']) {
      expect(parseHibp(byName(n)).records, n).toEqual([]);
    }
    for (const flag of ['IsRetired', 'IsMalware']) {
      expect(parseHibp({ ...byName('Adobe'), [flag]: true }).records, flag).toEqual([]);
    }
  });

  it('throws on a missing or invalid name, count or flag, and on non-objects', () => {
    expect(() => parseHibp(JSON.parse(fixture('hibp', 'bad.json')))).toThrow();
    expect(() => parseHibp({ ...byName('Adobe'), Name: '../x' })).toThrow();
    expect(() => parseHibp({ ...byName('Adobe'), PwnCount: -1 })).toThrow();
    expect(() => parseHibp({ ...byName('Adobe'), PwnCount: 1.5 })).toThrow();
    expect(() => parseHibp({ ...byName('Adobe'), IsVerified: 'yes' })).toThrow();
    expect(() => parseHibp('not json')).toThrow();
    expect(() => parseHibp([])).toThrow();
    expect(() => parseHibp(null)).toThrow();
  });

  it('reports unknown keys by name', () => {
    const out = parseHibp(fixture('hibp', 'extra-key.json'));
    expect(out.unknownFields).toEqual(['IsNewFlag']);
    expect(out.records).toHaveLength(1);
    expect(parseHibp(byName('Adobe')).unknownFields).toEqual([]);
  });

  it('a JSON string and an object give equal output; latestbreach parses', () => {
    expect(parseHibp(JSON.stringify(byName('Adobe')))).toEqual(parseHibp(byName('Adobe')));
    expect(parseHibp(fixture('hibp', 'latestbreach.json')).unknownFields).toEqual([]);
  });

  it('dates, titles and data types are cleaned and capped', () => {
    const base = byName('Adobe');
    const r = parseHibp({
      ...base,
      Title: '  ',
      BreachDate: '2013-02-30',
      DataClasses: [' A ', 'A', '', ...Array.from({ length: 40 }, (_, i) => `T${i}`)],
    }).records[0] as NoticeRecord;
    expect(r.rawName).toBe('Adobe');
    expect(r.occurredFrom).toBeUndefined();
    expect(r.dataTypes).toHaveLength(MAX_DATA_TYPES);
    expect(r.dataTypes?.[0]).toBe('A');
  });

  it('keeps no description, logo, attribution, disclosure URL or domain', () => {
    const notices = entries.flatMap((e) => parseHibp(e).records);
    const text = JSON.stringify(notices);
    for (const e of entries) {
      const desc = String(e.Description).trim();
      expect(text).not.toContain(desc.slice(0, 40));
      expect(text).not.toContain(String(e.LogoPath));
    }
    expect(text).not.toContain('adobe.com');
    expect(text).not.toContain('Attribution');
  });
});

describe('cisa-advisories', () => {
  const parseAll = (file: string) => feedItems(file).map((i) => parseCisaAdvisory(i));

  it('gives 1 + 6 + 1 records, none for the KEV announcement or the resource', () => {
    const per = parseAll('all.xml').map((o) => o.records);
    expect(per.map((r) => r.length)).toEqual([1, 6, 1, 0, 0]);
    const ids = per.flat().map((r) => r.sourceId);
    expect(ids[0]).toBe('ICSA-26-323-03:CVE-2026-31001');
    expect(ids).toContain('CISA-25817:CVE-2026-33333');
    expect(ids.filter((i) => i.startsWith('ICSA-26-321-01:'))).toHaveLength(6);
    expect(parseAll('all.xml').flatMap((o) => o.unknownFields)).toEqual([]);
  });

  it('record fields', () => {
    const r = parseAll('all.xml')[0]?.records[0] as AdvisoryRecord;
    expect(r).toEqual({
      source: 'cisa-advisories',
      sourceId: 'ICSA-26-323-03:CVE-2026-31001',
      vulnKey: 'CVE-2026-31001',
      status: 'active',
      published: '2026-11-19T12:00:00.000Z',
      modified: '2026-11-19T12:00:00.000Z',
      url: 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-323-03',
    });
  });

  it('deduplicates CVEs in first-seen order, case-insensitively', () => {
    const ids = parseAll('all.xml')[1]?.records.map((r) => r.vulnKey);
    expect(ids).toEqual([1, 2, 3, 4, 5, 6].map((i) => `CVE-2026-3${2000 + i}`));
  });

  it('caps a 120-CVE advisory and reads a four-digit-year date', () => {
    const recs = parseAll('aa-advisory.xml')[0]?.records as AdvisoryRecord[];
    expect(recs).toHaveLength(MAX_CVES_PER_ADVISORY);
    expect(recs.every((r) => r.sourceId.startsWith('AA26-310A:CVE-2026-'))).toBe(true);
    expect(recs[0]?.published).toBe('2026-11-07T09:30:00.000Z');
  });

  it('advisoryId', () => {
    expect(advisoryId('https://www.cisa.gov/news-events/ics-advisories/icsa-26-323-03', '')).toBe(
      'ICSA-26-323-03',
    );
    expect(advisoryId('https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-100-01a', '')).toBe(
      'ICSMA-25-100-01A',
    );
    expect(advisoryId('https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-310a', '')).toBe(
      'AA26-310A',
    );
    expect(advisoryId('https://www.cisa.gov/news-events/alerts/2026/11/17/x', '/node/25817')).toBe(
      'CISA-25817',
    );
    expect(advisoryId('https://www.cisa.gov/news-events/alerts/2026/11/17/x', 'abc')).toBeNull();
  });

  it('throws without an ID, with a bad date, or on a non-object', () => {
    const base = {
      title: 'x CVE-2026-0001',
      link: 'https://www.cisa.gov/news-events/alerts/2026/11/17/x',
      description: '',
      pubDate: 'Tue, 17 Nov 26 15:30:00 +0000',
      guid: { '#text': '/node/1', '@_isPermaLink': 'false' },
    };
    expect(parseCisaAdvisory(base).records).toHaveLength(1);
    expect(() => parseCisaAdvisory({ ...base, guid: 'icsa-26-1' })).toThrow();
    expect(() => parseCisaAdvisory({ ...base, pubDate: 'yesterday' })).toThrow();
    expect(() => parseCisaAdvisory({ ...base, pubDate: 'Tue, 31 Feb 26 15:30:00 +0000' })).toThrow();
    expect(() => parseCisaAdvisory('nope')).toThrow();
    expect(() => parseCisaAdvisory([])).toThrow();
    expect(parseCisaAdvisory(JSON.stringify(base))).toEqual(parseCisaAdvisory(base));
  });

  it('converts zones to UTC and reports unknown keys', () => {
    const base = {
      title: 'CVE-2026-0001',
      link: 'https://www.cisa.gov/news-events/alerts/2026/11/17/x',
      guid: '/node/1',
      'dc:creator': 'CISA',
      category: 'x',
      extra: 1,
    };
    const at = (pubDate: string) => parseCisaAdvisory({ ...base, pubDate }).records[0]?.published;
    expect(at('Tue, 17 Nov 26 23:30 -0100')).toBe('2026-11-18T00:30:00.000Z');
    expect(at('17 Nov 2026 10:00:00 GMT')).toBe('2026-11-17T10:00:00.000Z');
    expect(parseCisaAdvisory({ ...base, pubDate: '17 Nov 26 10:00 Z' }).unknownFields).toEqual(['extra']);
  });

  it('skips other hosts and paths', () => {
    const base = { title: 'CVE-2026-0001', pubDate: '17 Nov 26 10:00 Z', guid: '/node/1' };
    for (const link of [
      'https://example.com/news-events/alerts/x',
      'http://www.cisa.gov/news-events/alerts/x',
      'https://www.cisa.gov/resources-tools/x',
    ]) {
      expect(parseCisaAdvisory({ ...base, link }).records, link).toEqual([]);
    }
  });

  it('keeps no description text', () => {
    const text = JSON.stringify(parseAll('all.xml').flatMap((o) => o.records));
    for (const marker of ['ZEBRA-HARBOR', 'QUARTZ-MEADOW', 'LANTERN-FJORD', 'filler paragraph', '<p>']) {
      expect(text).not.toContain(marker);
    }
  });
});

describe('vcdb', () => {
  const FILES = ['full-date.json', 'year-month.json', 'no-victim.json'];
  const gitFile = (text: string | null, status: 'added' | 'removed' = 'added') => ({
    path: 'data/json/submitted/x.json',
    status,
    text,
  });
  const one = (file: string): IncidentRecord => {
    const out = parseVcdb(gitFile(fixture('vcdb', file)));
    expect(out.records).toHaveLength(1);
    return out.records[0] as IncidentRecord;
  };

  it('GitFile, JSON string and object give equal output', () => {
    for (const f of FILES) {
      const text = fixture('vcdb', f);
      const a = parseVcdb(gitFile(text));
      expect(parseVcdb(text), f).toEqual(a);
      expect(parseVcdb(JSON.parse(text)), f).toEqual(a);
    }
  });

  it('full-date file', () => {
    expect(one('full-date.json')).toEqual({
      source: 'vcdb',
      incidentId: '0565817A-B21A-4B22-BEDA-A2ED74A3DC7B',
      kind: 'cyber_event',
      title: expect.stringMatching(/^All About Women's Care: Hacking( \(.+\))?$/),
      date: '2026-04-09',
      entities: ["All About Women's Care"],
      url: expect.stringMatching(/^https:\/\/www\.classaction\.org\//),
    });
  });

  it('year-and-month file has no date', () => {
    const r = one('year-month.json');
    expect(r.title).toBe('NAS Recovery Solutions: Misuse (Privilege abuse)');
    expect(r.date).toBeUndefined();
    expect(r.entities).toEqual(['NAS Recovery Solutions']);
    expect(r.url).toMatch(/^https:\/\/www\.hipaajournal\.com\//);
    expect(r.techniques).toBeUndefined();
  });

  it('no-victim file: unnamed, no entities, GitHub issue link', () => {
    const r = one('no-victim.json');
    expect(r.title).toBe('Unnamed organisation: Misuse (Privilege abuse)');
    expect(r.entities).toBeUndefined();
    expect(r.url).toBe('https://github.com/vz-risk/VCDB/issues/23768');
  });

  it('skips suspected incidents and removed or empty files', () => {
    expect(parseVcdb(gitFile(fixture('vcdb', 'suspected.json'))).records).toEqual([]);
    expect(parseVcdb(gitFile(null, 'removed')).records).toEqual([]);
    expect(parseVcdb(gitFile(fixture('vcdb', 'full-date.json'), 'removed')).records).toEqual([]);
    expect(parseVcdb(gitFile(null)).records).toEqual([]);
  });

  it('throws on a bad ID, bad JSON or a non-object', () => {
    expect(() => parseVcdb(gitFile(fixture('vcdb', 'bad-id.json')))).toThrow();
    expect(() => parseVcdb(gitFile('{not json'))).toThrow();
    expect(() => parseVcdb('[]')).toThrow();
    expect(() => parseVcdb(42)).toThrow();
    expect(() => parseVcdb({ security_incident: 'Confirmed' })).toThrow();
  });

  it('title edge cases: no action, unknown variety, long victim; unknown keys', () => {
    const base = JSON.parse(fixture('vcdb', 'year-month.json')) as Record<string, unknown>;
    const { action: _a, ...noAction } = base;
    expect(parseVcdb(noAction).records[0]?.title).toBe('NAS Recovery Solutions: incident');
    expect(parseVcdb({ ...base, action: { error: { variety: ['Unknown'] } } }).records[0]?.title).toBe(
      'NAS Recovery Solutions: Error',
    );
    const long = parseVcdb({ ...base, victim: { victim_id: 'V'.repeat(500) } }).records[0];
    expect(long?.title).toHaveLength(MAX_TITLE);
    expect(parseVcdb({ ...base, brand_new: 1 }).unknownFields).toEqual(['brand_new']);
    expect(parseVcdb(base).unknownFields).toEqual([]);
  });

  it('keeps no summary or analyst text', () => {
    const texts: string[] = [];
    const collect = (v: unknown, key = ''): void => {
      if (typeof v === 'string' && /summary|notes/.test(key) && v.length > 10) texts.push(v);
      else if (Array.isArray(v)) for (const x of v) collect(x, key);
      else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) collect(x, k);
    };
    const out: string[] = [];
    for (const f of [...FILES, 'suspected.json']) {
      const o = JSON.parse(fixture('vcdb', f));
      collect(o);
      out.push(JSON.stringify(parseVcdb(o).records));
    }
    expect(texts.length).toBeGreaterThan(0);
    for (const t of texts) for (const o of out) expect(o).not.toContain(t.slice(0, 30));
  });
});

describe('loadParser', () => {
  it('resolves hibp, cisa-advisories and vcdb', async () => {
    for (const n of ['hibp', 'cisa-advisories', 'vcdb']) {
      expect(typeof (await loadParser(n)).parse, n).toBe('function');
    }
  });
});
