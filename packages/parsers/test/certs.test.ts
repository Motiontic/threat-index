import type { AdvisoryRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { vulnId } from '../../linker/src/clean';
import { link } from '../../linker/src/link';
import { makeFake, vulnRow } from '../../linker/src/testing/fake-deps';
import { parseFeed } from '../../patterns/src/feed';
import { parse as parseBund, parseCertBund } from '../src/cert-bund';
import { CERT_CC_NOTE_KEYS, parse as parseCc, parseCertCcEntry, parseCertCcNote } from '../src/cert-cc';
import { cveList, isoMs, MAX_CVES_PER_ADVISORY, perCve } from '../src/cert-common';
import { parseJvn } from '../src/jvn';

const entries = parseFeed(fixture('cert-cc', 'atomfeed.xml'));
const note = JSON.parse(fixture('cert-cc', 'note-604762.json')) as Record<string, unknown>;
const bund = (f: string) => parseCertBund(fixture('bsi-cert-bund', f));
const ids = (r: AdvisoryRecord[]) => r.map((x) => x.sourceId);
const keys = (r: AdvisoryRecord[]) => r.map((x) => x.vulnKey);

const CC_CVES = ['CVE-2026-45110', 'CVE-2026-49401', 'CVE-2026-59890', 'CVE-2026-14978'];

describe('cert-common', () => {
  it('isoMs normalises to milliseconds UTC and rejects bad dates', () => {
    expect(isoMs('2026-11-19T15:40+09:00')).toBe('2026-11-19T06:40:00.000Z');
    expect(isoMs('2026-11-22T23:00:00+0000')).toBe('2026-11-22T23:00:00.000Z');
    expect(isoMs('2026-11-17T17:12:49.354980+00:00')).toBe('2026-11-17T17:12:49.354Z');
    expect(isoMs('2026-11-16T16:17:31Z')).toBe('2026-11-16T16:17:31.000Z');
    expect(isoMs('2026-02-31T00:00:00Z')).toBeNull();
    expect(isoMs('2026-11-16')).toBeNull();
    expect(isoMs('2026-11-16T25:00:00Z')).toBeNull();
    expect(isoMs(5)).toBeNull();
  });

  it('cveList normalises, dedupes and caps', () => {
    expect(cveList(['cve-2026-0001', ' CVE-2026-0001 ', 'x', 5, 'CVE-2026-0002'])).toEqual([
      'CVE-2026-0001',
      'CVE-2026-0002',
    ]);
    const many = Array.from({ length: 1200 }, (_, i) => `CVE-2026-${String(i + 1000)}`);
    expect(cveList(many)).toHaveLength(MAX_CVES_PER_ADVISORY);
  });

  it('perCve fans out, falls back to a null key, and throws on unsafe ids', () => {
    const f = { source: 's', status: 'active' as const, modified: '2026-01-01T00:00:00.000Z' };
    expect(ids(perCve('A-1', ['CVE-2026-0001', 'CVE-2026-0002'], f))).toEqual([
      'A-1:CVE-2026-0001',
      'A-1:CVE-2026-0002',
    ]);
    expect(perCve('A-1', [], f)).toEqual([{ ...f, sourceId: 'A-1', vulnKey: null }]);
    expect(() => perCve('VU#1', [], f)).toThrow();
    expect(() => perCve('A'.repeat(130), [], f)).toThrow();
  });
});

describe('cert-cc', () => {
  it('feed entries: CVE IDs block only, never prose', () => {
    expect(entries).toHaveLength(3);
    const a = parseCertCcEntry(entries[0]);
    expect(a.records).toHaveLength(4);
    expect(keys(a.records)).toEqual(CC_CVES);
    expect(keys(a.records)).not.toContain('CVE-2026-49999');
    expect(ids(a.records)[0]).toBe('VU-604762:CVE-2026-45110');
    expect(a.records[0]).toMatchObject({
      source: 'cert-cc',
      status: 'active',
      url: 'https://kb.cert.org/vuls/id/604762',
      published: '2026-11-16T16:17:31.751Z',
      modified: '2026-11-17T17:12:49.354Z',
    });
    expect(a.unknownFields).toEqual([]);
    const b = parseCertCcEntry(entries[1]);
    expect(ids(b.records)).toEqual(['VU-644655:CVE-2026-128321']);
    const c = parseCertCcEntry(entries[2]);
    expect(c.records).toEqual([
      expect.objectContaining({
        sourceId: 'VU-124705',
        vulnKey: null,
        url: 'https://kb.cert.org/vuls/id/124705',
      }),
    ]);
  });

  it('note JSON gives the same CVE set as the feed entry', () => {
    const n = parseCertCcNote(note);
    expect(new Set(keys(n.records))).toEqual(new Set(keys(parseCertCcEntry(entries[0]).records)));
    expect(n.unknownFields).toEqual([]);
    expect(n.records[0]?.published).toBe('2026-11-16T16:17:31.751Z');
    expect(parseCc(JSON.stringify(note)).records).toHaveLength(4);
    expect(parseCc(note).records).toHaveLength(4);
    expect(parseCc(entries[0]).records).toHaveLength(4);
  });

  it('reports unknown keys and throws on a bad id or missing date', () => {
    expect(parseCertCcNote({ ...note, newthing: 1 }).unknownFields).toEqual(['newthing']);
    expect(parseCertCcEntry({ ...(entries[0] as object), extra: 1 }).unknownFields).toEqual(['extra']);
    expect(CERT_CC_NOTE_KEYS).toContain('cveids');
    expect(() =>
      parseCertCcEntry({ ...(entries[0] as object), id: 'https://evil.example/vuls/id/1' }),
    ).toThrow();
    expect(() => parseCertCcEntry({ ...(entries[0] as object), id: 'VU#604762' })).toThrow();
    expect(() => parseCertCcEntry({ ...(entries[0] as object), updated: 'x', published: 'y' })).toThrow();
    expect(() => parseCertCcNote({ ...note, idnumber: '../x' })).toThrow();
    expect(() => parseCc('not json')).toThrow();
  });
});

describe('jvn', () => {
  const out = parseJvn(fixture('jvn', 'jvndb.rdf'));
  it('three items: one CVE, two CVEs, none', () => {
    expect(ids(out.records)).toEqual([
      'JVNDB-2026-000175:CVE-2026-129517',
      'JVNDB-2026-042618:CVE-2026-86578',
      'JVNDB-2026-042618:CVE-2026-86579',
      'JVNDB-2026-099999',
    ]);
    expect(keys(out.records)).toEqual(['CVE-2026-129517', 'CVE-2026-86578', 'CVE-2026-86579', null]);
    expect(out.records[0]).toMatchObject({
      source: 'jvn',
      status: 'active',
      published: '2026-11-19T06:40:00.000Z',
      modified: '2026-11-19T06:40:00.000Z',
      url: 'https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-000175.html',
    });
    expect(out.records[3]).toMatchObject({
      published: '2026-11-10T06:55:00.000Z',
      modified: '2026-11-13T04:54:00.000Z',
    });
    expect(out.unknownFields).toEqual(['item.sec:foo']);
  });

  it('bad id is skipped and reported; DOCTYPE and non-RDF throw', () => {
    const bad = parseJvn(fixture('jvn', 'bad-id.rdf'));
    expect(bad.records).toEqual([]);
    expect(bad.unknownFields).toEqual(['item.sec:identifier']);
    expect(() => parseJvn(`<!DOCTYPE x [<!ENTITY a "b">]>${fixture('jvn', 'jvndb.rdf')}`)).toThrow();
    expect(() => parseJvn('<rss></rss>')).toThrow();
    expect(() => parseJvn(5)).toThrow();
  });

  it('keeps 1,000 of 1,200 CVEs; falls back to dc:date and a built url', () => {
    const refs = Array.from(
      { length: 1200 },
      (_, i) => `<sec:references source="CVE" id="CVE-2026-${1000 + i}">x</sec:references>`,
    ).join('');
    const doc = `<rdf:RDF><item><link>http://elsewhere.test/</link><sec:identifier>JVNDB-2026-000001</sec:identifier>${refs}<dc:date>2026-01-02T03:04+09:00</dc:date></item></rdf:RDF>`;
    const r = parseJvn(doc);
    expect(r.records).toHaveLength(1000);
    expect(r.records[0]).toMatchObject({
      modified: '2026-01-01T18:04:00.000Z',
      url: 'https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-000001.html',
    });
    expect(r.records[0]?.published).toBeUndefined();
    const nodate = parseJvn(
      '<rdf:RDF><item><sec:identifier>JVNDB-2026-000001</sec:identifier></item></rdf:RDF>',
    );
    expect(nodate.records).toEqual([]);
    expect(nodate.unknownFields).toEqual(['item.dcterms:modified']);
  });
});

describe('cert-bund', () => {
  it('real document: ten CVEs, portal url, dates', () => {
    const r = bund('wid-sec-w-2026-4715.json');
    expect(r.records).toHaveLength(10);
    expect(ids(r.records)[0]).toBe('WID-SEC-W-2026-4715:CVE-2026-59296');
    expect(r.records[0]).toMatchObject({
      source: 'bsi-cert-bund',
      status: 'active',
      published: '2026-11-19T23:00:00.000Z',
      modified: '2026-11-22T23:00:00.000Z',
      url: 'https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4715',
    });
    expect(r.unknownFields).toEqual([]);
    expect(
      parseBund({ ref: 'x', time: 't', text: fixture('bsi-cert-bund', 'wid-sec-w-2026-4715.json') }).records,
    ).toHaveLength(10);
  });

  it('no CVE gives one null-key record; AMBER, null text and draft give none', () => {
    const n = bund('no-cve.json');
    expect(n.records).toEqual([expect.objectContaining({ sourceId: 'WID-SEC-W-2026-0002', vulnKey: null })]);
    expect(bund('amber.json')).toEqual({ records: [], unknownFields: ['tlp'] });
    expect(parseBund({ ref: 'x', time: 't', text: null }).records).toEqual([]);
    const d = JSON.parse(fixture('bsi-cert-bund', 'no-cve.json'));
    d.document.tracking.status = 'draft';
    expect(parseCertBund(d).records).toEqual([]);
  });

  it('withdrawn, unknown fields, and throws', () => {
    const d = JSON.parse(fixture('bsi-cert-bund', 'wid-sec-w-2026-4715.json'));
    d.document.category = 'csaf_withdrawn';
    d.document.surprise = 1;
    d.other = 1;
    const r = parseCertBund(d);
    expect(r.records[0]?.status).toBe('withdrawn');
    expect(r.unknownFields).toEqual(['other', 'document.surprise']);
    expect(() => parseCertBund('{nope')).toThrow();
    expect(() => parseCertBund([])).toThrow();
    d.document.tracking.id = 'WID-SEC-2026-4715';
    expect(() => parseCertBund(d)).toThrow();
    d.document.tracking.id = 'WID-SEC-W-2026-4715';
    d.document.tracking.current_release_date = 'soon';
    expect(() => parseCertBund(d)).toThrow();
  });
});

describe('all records', () => {
  const all: AdvisoryRecord[] = [
    ...entries.flatMap((e) => parseCertCcEntry(e).records),
    ...parseCertCcNote(note).records,
    ...parseJvn(fixture('jvn', 'jvndb.rdf')).records,
    ...bund('wid-sec-w-2026-4715.json').records,
    ...bund('no-cve.json').records,
  ];
  it('every sourceId passes the linker vulnId rule unchanged', () => {
    for (const r of all) expect(vulnId(r.sourceId), r.sourceId).toBe(r.sourceId);
  });

  it('link() puts each CVE advisory on its CVE hub', async () => {
    const f = makeFake();
    const recs = [
      ...entries.flatMap((e) => parseCertCcEntry(e).records),
      ...bund('wid-sec-w-2026-4715.json').records,
    ];
    // A hub is written only when it is stored (hot) already, so seed the CVE hubs the advisories name.
    for (const k of new Set(recs.map((r) => r.vulnKey))) if (k) f.put('vulns', vulnRow(k));
    const out = await link(recs, f.deps);
    f.apply(out.rows);
    const advs = f.all('advisories');
    for (const r of recs.filter((x) => x.vulnKey)) {
      expect(advs.find((a) => a.source === r.source && a.source_id === r.sourceId)?.vuln_key).toBe(r.vulnKey);
      expect(f.all('vulns').some((v) => v.key === r.vulnKey)).toBe(true);
    }
  });
});
