import type { AdvisoryRecord, SignalRecord, VulnRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch as fingerprintFetch } from '../../patterns/src/fingerprint';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { parseEuvd, parseEuvdDate } from '../src/euvd';
import { parseGcveSightings } from '../src/gcve-sighting';
import { parseProjectZeroRow } from '../src/project-zero';

const PZ_URL = SOURCE_BY_ID.get('project-zero')?.pull?.fingerprint?.url as string;

async function pzSignals(): Promise<{ signals: SignalRecord[]; unknown: string[]; items: number }> {
  const source = SOURCE_BY_ID.get('project-zero');
  if (!source) throw new Error('no project-zero source');
  const h = makeCtx({
    source,
    routes: [route(PZ_URL, reply(fixture('project-zero', 'all.csv'), 200, { 'content-type': 'text/csv' }))],
  });
  const res = await fingerprintFetch(h.ctx);
  const signals: SignalRecord[] = [];
  const unknown: string[] = [];
  for (const item of res.items) {
    const out = parseProjectZeroRow(item.body);
    signals.push(...out.records);
    unknown.push(...out.unknownFields);
  }
  return { signals, unknown, items: res.items.length };
}

describe('project-zero', () => {
  it('one signal per CVE row through the fingerprint pattern; empty rows and "-" give none', async () => {
    const { signals, unknown, items } = await pzSignals();
    expect(items).toBe(6); // the "-" row has a key cell; the empty rows are dropped
    expect(unknown).toEqual([]);
    expect(signals.map((s) => s.vulnKey)).toEqual([
      'CVE-2026-125350',
      'CVE-2026-96951',
      'CVE-2024-53197',
      'CVE-2022-26485',
      'CVE-2024-7262',
    ]);
    const by = (k: string) => signals.find((s) => s.vulnKey === k) as SignalRecord;
    expect(by('CVE-2024-53197')).toEqual({
      vulnKey: 'CVE-2024-53197',
      kind: 'exploited_wild',
      source: 'project-zero',
      ref: 'CVE-2024-53197',
      firstSeen: '2024-11-20',
      evidenceDate: '2025-04-01',
      url: expect.stringMatching(/^https:\/\//),
    });
    expect(by('CVE-2022-26485')).toMatchObject({
      firstSeen: '2022-03-05',
      evidenceDate: '2022-03-05',
      url: 'https://www.mozilla.org/en-US/security/advisories/mfsa2022-09/',
    });
    expect(by('CVE-2024-7262')).toMatchObject({ firstSeen: '2024-02-29' });
    expect(by('CVE-2024-7262')?.evidenceDate).toBeUndefined();
    for (const s of signals) {
      expect(s.url ?? '').not.toContain('???');
      expect(s.firstSeen).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it('prefers the analysis URL, falls back to the advisory', () => {
    const base = { CVE: 'cve-2024-1', 'Date Patched': '2024-01-02' };
    const row = (extra: Record<string, string>) =>
      parseProjectZeroRow({ ...base, CVE: 'CVE-2024-0001', ...extra }).records[0];
    expect(row({ 'Analysis URL': 'https://a.test/x', Advisory: 'https://b.test/y' })?.url).toBe(
      'https://a.test/x',
    );
    expect(row({ 'Analysis URL': '???', Advisory: 'https://b.test/y' })?.url).toBe('https://b.test/y');
    expect(row({ 'Analysis URL': 'javascript:alert(1)', Advisory: '???' })?.url).toBeUndefined();
  });

  it('splits several CVEs in one cell, and takes JSON text', () => {
    const out = parseProjectZeroRow(
      JSON.stringify({
        CVE: 'CVE-2024-0001, cve-2024-0002\nnope',
        'Date Discovered': '2024-02-30',
        'Date Patched': '2024-03-01',
      }),
    );
    expect(out.records.map((r) => [r.vulnKey, r.firstSeen])).toEqual([
      ['CVE-2024-0001', '2024-03-01'],
      ['CVE-2024-0002', '2024-03-01'],
    ]);
  });

  it('a row with no date gives no record', () => {
    expect(parseProjectZeroRow({ CVE: 'CVE-2024-0001', 'Date Discovered': '???' }).records).toEqual([]);
  });

  it('reports an extra column once, throws on non-objects and a missing CVE key', () => {
    const out = parseProjectZeroRow({ CVE: 'CVE-2024-0001', 'Date Patched': '2024-03-01', Extra: 'x' });
    expect(out.unknownFields).toEqual(['Extra']);
    expect(() => parseProjectZeroRow('nope')).toThrow(/^project-zero:/);
    expect(() => parseProjectZeroRow(['CVE'])).toThrow(/^project-zero:/);
    expect(() => parseProjectZeroRow(null)).toThrow(/^project-zero:/);
    expect(() => parseProjectZeroRow({ Vendor: 'x' })).toThrow(/^project-zero:/);
  });
});

describe('euvd', () => {
  it('parseEuvdDate', () => {
    expect(parseEuvdDate('Nov 20, 2026, 12:00:00 AM')).toBe('2026-11-20T00:00:00.000Z');
    expect(parseEuvdDate('Nov 20, 2026, 12:30:00 PM')).toBe('2026-11-20T12:30:00.000Z');
    expect(parseEuvdDate('Apr 12, 2024, 7:20:00 AM')).toBe('2024-04-12T07:20:00.000Z');
    expect(parseEuvdDate('Nov 20, 2026, 10:30:42 PM')).toBe('2026-11-20T22:30:42.000Z');
    expect(parseEuvdDate('2024-04-12T07:20:00.707Z')).toBe('2024-04-12T07:20:00.707Z');
    expect(parseEuvdDate('Feb 30, 2026, 1:00:00 AM')).toBeNull();
    expect(parseEuvdDate('2026-02-30T00:00:00Z')).toBeNull();
    expect(parseEuvdDate('Nov 20, 2026, 13:00:00 PM')).toBeNull();
    expect(parseEuvdDate('yesterday')).toBeNull();
  });

  const search = fixture('enisa', 'exploited-search.json');

  it('search fixture: advisory with the CVE and an exploited_wild signal keyed by the CVE', () => {
    const out = parseEuvd(search);
    expect(out.unknownFields).toEqual([]);
    const advs = out.records.filter((r): r is AdvisoryRecord => 'sourceId' in r);
    const sigs = out.records.filter((r): r is SignalRecord => 'ref' in r);
    expect(out.records.some((r) => 'key' in r)).toBe(false);
    expect(advs).toHaveLength(3);
    expect(advs[0]).toEqual({
      source: 'enisa',
      sourceId: 'EUVD-2026-119377',
      vulnKey: 'CVE-2026-114713',
      status: 'active',
      published: '2026-11-08T02:31:48.000Z',
      modified: '2026-11-23T12:07:21.000Z',
      url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-119377',
    });
    expect(sigs[0]).toEqual({
      vulnKey: 'CVE-2026-114713',
      kind: 'exploited_wild',
      source: 'enisa',
      ref: 'EUVD-2026-119377',
      firstSeen: '2026-11-13',
      evidenceDate: '2026-11-13',
      url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-119377',
    });
  });

  it('no-cve.json: an euvd vuln and an advisory with a null vulnKey; the unknown field is reported', () => {
    const out = parseEuvd(fixture('enisa', 'no-cve.json'));
    expect(out.unknownFields).toEqual(['vendorNotes']);
    const v = out.records.find((r): r is VulnRecord => 'key' in r) as VulnRecord;
    expect(v).toMatchObject({
      key: 'EUVD-2026-900001',
      kind: 'euvd',
      source: 'enisa',
      cvss: 8.7,
      cvssVersion: '4.0',
      cvssSource: 'example',
      cwe: [],
      aliases: ['GHSA-aaaa-bbbb-cccc'],
      modified: '2026-11-21T15:45:10.000Z',
    });
    expect(v.title).toBe(
      'Example Widget Server before 2.4.1 allows a remote attacker to read arbitrary files through a crafted request.',
    );
    expect(out.records.find((r): r is AdvisoryRecord => 'sourceId' in r)?.vulnKey).toBeNull();
    expect(out.records.find((r): r is SignalRecord => 'ref' in r)).toMatchObject({
      vulnKey: 'EUVD-2026-900001',
      ref: 'EUVD-2026-900001',
      firstSeen: '2026-11-15',
    });
  });

  it('array, single entry and pattern-cut forms give the same records', () => {
    const items = (JSON.parse(search) as { items: unknown[]; total: number }).items;
    const whole = parseEuvd(search).records;
    expect(parseEuvd(items).records).toEqual(whole);
    expect(parseEuvd(JSON.stringify(items)).records).toEqual(whole);
    const one = parseEuvd(items[0]).records;
    expect(parseEuvd({ items: [items[0]], total: 1809 }).records).toEqual(one);
    expect(whole.slice(0, one.length)).toEqual(one);
    const entry = parseEuvd(fixture('enisa', 'entry.json'));
    expect(entry.unknownFields).toEqual([]);
    expect(entry.records).toHaveLength(2);
    expect(entry.records[0]).toMatchObject({ sourceId: 'EUVD-2024-31989', vulnKey: 'CVE-2024-3400' });
  });

  it('throws on a missing dateUpdated or an odd document; skips entries without a usable id', () => {
    expect(() => parseEuvd({ id: 'EUVD-2026-1', description: 'x' })).toThrow(
      /^euvd: EUVD-2026-1: missing or invalid dateUpdated/,
    );
    expect(() => parseEuvd('{oops')).toThrow(/^euvd:/);
    expect(() => parseEuvd(42)).toThrow(/^euvd:/);
    expect(() => parseEuvd({ foo: 1 })).toThrow(/^euvd:/);
    expect(parseEuvd({ items: [{ id: 'nope' }, { description: 'x' }], total: 2 })).toEqual({
      records: [],
      unknownFields: [],
    });
  });

  it('cuts a long summary at a word boundary and uses the id as title for a long first sentence', () => {
    const long = `${'word '.repeat(80)}end.`;
    const out = parseEuvd({
      id: 'EUVD-2026-5',
      dateUpdated: 'Nov 1, 2026, 1:00:00 AM',
      description: long,
      baseScore: 11,
      baseScoreVersion: '3.1',
    });
    const v = out.records.find((r): r is VulnRecord => 'key' in r) as VulnRecord;
    expect(v.summary.length).toBeLessThanOrEqual(300);
    expect(v.summary.endsWith('word')).toBe(true);
    expect(v.title).toBe('EUVD-2026-5');
    expect(v.cvss).toBeUndefined();
  });
});

describe('gcve-sighting', () => {
  const doc = fixture('gcve', 'sightings.json');

  it('exploited → exploited_wild, proof-of-concept → poc, seen → nothing; ref is the UUID', () => {
    const out = parseGcveSightings(doc);
    expect(out.unknownFields).toEqual([]);
    expect(out.records).toHaveLength(4);
    expect(out.records[0]).toEqual({
      vulnKey: 'CVE-2026-134624',
      kind: 'exploited_wild',
      source: 'gcve',
      ref: 'b4d50577-798c-4495-8b16-a12ed8cdf386',
      firstSeen: '2026-11-23',
      url: 'https://db.gcve.eu/known-exploited-vulnerabilities-catalog/e720a52c-ae39-4ed7-a22c-ea67dbe6b0fb',
    });
    const poc = out.records.filter((r) => r.kind === 'poc');
    expect(poc).toHaveLength(1);
    expect(poc[0]?.ref).toBe('6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f');
    expect(out.records.some((r) => r.vulnKey === 'CVE-2026-133968' && r.ref.startsWith('7a2d'))).toBe(false);
  });

  it('takes a single sighting, skips unsafe ids, bad uuids and bad dates', () => {
    const one = (JSON.parse(doc) as { data: Record<string, unknown>[] }).data[0] as Record<string, unknown>;
    expect(parseGcveSightings(one).records).toHaveLength(1);
    expect(parseGcveSightings({ ...one, vulnerability: 'CVE-2026-1 <script>' }).records).toEqual([]);
    expect(parseGcveSightings({ ...one, uuid: 'not-a-uuid' }).records).toEqual([]);
    expect(parseGcveSightings({ ...one, creation_timestamp: 'garbage' }).records).toEqual([]);
    expect(parseGcveSightings({ ...one, extra: 1 }).unknownFields).toEqual(['extra']);
  });

  it('throws on anything else', () => {
    expect(() => parseGcveSightings('{oops')).toThrow(/^gcve-sighting:/);
    expect(() => parseGcveSightings(7)).toThrow(/^gcve-sighting:/);
    expect(() => parseGcveSightings({ foo: 1 })).toThrow(/^gcve-sighting:/);
  });
});
