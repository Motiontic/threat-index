import type { AdvisoryRecord, SignalRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { fetch as changelistFetch } from '../../patterns/src/changelist';
import { makeCtx, ranged, reply, route } from '../../patterns/test/helpers';
import { AFFECTED_MAX, CSAF_PUBLISHERS, parse, parseCsaf } from '../src/csaf';

const advisories = (r: { records: unknown[] }) =>
  r.records.filter((x) => 'sourceId' in (x as object)) as AdvisoryRecord[];
const signals = (r: { records: unknown[] }) =>
  r.records.filter((x) => 'kind' in (x as object)) as SignalRecord[];

describe('csaf: vendor documents', () => {
  it('Red Hat VEX: bare CVE sourceId, fixed first then not affected, no signal', () => {
    const r = parseCsaf(fixture('red-hat', 'cve-2023-38545.json'));
    const [adv] = advisories(r);
    expect(r.records).toHaveLength(1);
    expect(adv).toMatchObject({
      source: 'red-hat',
      sourceId: 'CVE-2023-38545',
      vulnKey: 'CVE-2023-38545',
      status: 'active',
      url: 'https://access.redhat.com/security/cve/CVE-2023-38545',
    });
    const affected = adv?.affected ?? [];
    expect(affected.length).toBeLessThanOrEqual(AFFECTED_MAX);
    const firstNot = affected.findIndex((a) => a.range === 'not affected');
    expect(firstNot).toBeGreaterThan(0);
    expect(affected.slice(0, firstNot).every((a) => a.ecosystem === 'Red Hat' && a.fixed)).toBe(true);
    expect(affected[0]?.fixed).toBe('puppet-agent-0:7.27.0-1.el6sat.i686');
    expect(affected.slice(firstNot).every((a) => a.range === 'not affected')).toBe(true);
    expect(signals(r)).toEqual([]);
    expect(r.unknownFields).toEqual([]);
  });

  it('MSRC: Exploited:Yes gives one signal with the right days; Exploited:No gives none', () => {
    const r = parseCsaf(fixture('msrc', 'msrc_cve-2024-38193.json'));
    expect(advisories(r)).toHaveLength(1);
    expect(advisories(r)[0]).toMatchObject({
      source: 'msrc',
      sourceId: 'msrc_CVE-2024-38193:CVE-2024-38193',
      vulnKey: 'CVE-2024-38193',
      url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38193',
    });
    expect(advisories(r)[0]?.affected?.some((a) => a.fixed)).toBe(true);
    expect(signals(r)).toEqual([
      {
        vulnKey: 'CVE-2024-38193',
        kind: 'exploited_wild',
        source: 'msrc',
        ref: 'msrc_CVE-2024-38193',
        firstSeen: '2024-08-13',
        evidenceDate: '2024-08-13',
        url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38193',
      },
    ]);
    const no = parseCsaf(fixture('msrc', 'msrc_cve-2026-70197.json'));
    expect(signals(no)).toEqual([]);
    expect(advisories(no)[0]?.url).toMatch(/update-guide\/vulnerability\/CVE-2026-70197$/);
    for (const a of [...advisories(r), ...advisories(no)]) expect(a.url).not.toMatch(/\.json$/);
  });

  it('Cisco: one advisory per CVE, tracking id and CVE in the sourceId, advisory page url', () => {
    const r = parseCsaf(fixture('cisco', 'cisco-sa-fmc-mulivulns-4psnfwvx.json'));
    const advs = advisories(r);
    expect(advs).toHaveLength(5);
    for (const a of advs) {
      expect(a.source).toBe('cisco');
      expect(a.sourceId).toBe(`cisco-sa-fmc-mulivulns-4PsnFwvx:${a.vulnKey}`);
      expect(a.url).toMatch(/^https:\/\/sec\.cloudapps\.cisco\.com\/.*cisco-sa-fmc-mulivulns-4PsnFwvx$/);
    }
    expect(new Set(advs.map((a) => a.sourceId)).size).toBe(5);
  });

  it('Oracle: three advisories with the CPU page as url', () => {
    const advs = advisories(parseCsaf(fixture('oracle', 'cpujan2025csaf.json')));
    expect(advs).toHaveLength(3);
    for (const a of advs) {
      expect(a.source).toBe('oracle');
      expect(a.url).toBe('https://www.oracle.com/security-alerts/cpujan2025.html');
    }
  });
});

describe('csaf: inputs', () => {
  const text = fixture('msrc', 'msrc_cve-2024-38193.json');

  it('an object, its JSON text and a ChangeItem give the same records; text null gives none', () => {
    const a = parseCsaf(JSON.parse(text));
    const b = parseCsaf(text);
    const c = parse({ ref: '2024/msrc_cve-2024-38193.json', time: '2024-08-13T07:00:00Z', text });
    expect(b).toEqual(a);
    expect(c).toEqual(a);
    expect(a.records.length).toBe(2);
    expect(parse({ ref: 'x.json', time: '2026-01-01T00:00:00Z', text: null })).toEqual({
      records: [],
      unknownFields: [],
    });
  });

  it('throws csaf: errors for bad input', () => {
    expect(() => parse('{nope')).toThrow('csaf: not valid JSON');
    expect(() => parse({ hello: 1 })).toThrow(/^csaf: expected a CSAF document/);
    expect(() => parse(42)).toThrow(/^csaf: expected a CSAF document/);
    const doc = JSON.parse(text);
    delete doc.document.tracking.current_release_date;
    expect(() => parse(doc)).toThrow(/^csaf: document\.tracking\.current_release_date/);
    const old = JSON.parse(text);
    old.document.csaf_version = '1.2';
    expect(() => parse(old)).toThrow(/^csaf: document\.csaf_version/);
    const other = JSON.parse(text);
    other.document.publisher.namespace = 'https://example.test';
    expect(() => parse(other)).toThrow('csaf: unknown publisher example.test');
  });

  it('draft gives none; no-cve gives none and reports the unknown field; opts.source overrides', () => {
    expect(parse(fixture('msrc', 'draft.json'))).toEqual({ records: [], unknownFields: [] });
    expect(parse(fixture('msrc', 'no-cve.json'))).toEqual({
      records: [],
      unknownFields: ['document.x_unexpected'],
    });
    const other = JSON.parse(text);
    other.document.publisher.namespace = 'https://example.test';
    const r = parseCsaf(other, { source: 'custom' });
    expect(advisories(r)[0]?.source).toBe('custom');
    expect(signals(r)[0]?.source).toBe('custom');
  });

  it('the publisher map covers the four vendors', () => {
    expect(new Set(Object.values(CSAF_PUBLISHERS))).toEqual(new Set(['red-hat', 'msrc', 'cisco', 'oracle']));
  });
});

describe('csaf: through the changelist pattern', () => {
  const run = async (id: string, list: string, body: string, ranges: boolean, cursorLine: number) => {
    const source = SOURCE_BY_ID.get(id);
    if (!source) throw new Error(`no ${id}`);
    const cfg = source.pull?.changelist;
    if (!cfg) throw new Error('no changelist');
    const lines = list.split('\n').filter(Boolean);
    const [ref, time] = (lines[cursorLine] ?? '').split(',').map((c) => c.replace(/"/g, '')) as [
      string,
      string,
    ];
    const h = makeCtx({
      source,
      cursor: { kind: 'timestamp', value: JSON.stringify([time, ref]) },
      routes: [
        route(
          cfg.listUrl,
          ranges
            ? ranged(list, { 'content-type': 'text/csv' })
            : reply(list, 200, { 'content-type': 'text/csv' }),
        ),
        route(
          new RegExp(`^${cfg.itemUrl.replace('{ref}', '.+').replace(/[.]/g, '\\.')}`.replace('\\.+', '.+')),
          reply(body),
        ),
      ],
    });
    return changelistFetch(h.ctx);
  };

  it('Red Hat (Range ignored) and MSRC (ranged): every item parses', async () => {
    for (const [id, file, ranges] of [
      ['red-hat', 'cve-2023-38545.json', false],
      ['msrc', 'msrc_cve-2024-38193.json', true],
    ] as const) {
      const res = await run(id, fixture(id, 'changes.csv'), fixture(id, file), ranges, 1);
      expect(res.items.length, id).toBeGreaterThan(0);
      for (const item of res.items) {
        const out = parse(item.body);
        expect(out.records.length, id).toBeGreaterThan(0);
        expect(out.unknownFields).toEqual([]);
      }
    }
  });
});
