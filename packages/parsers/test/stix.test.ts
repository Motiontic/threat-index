import type { AdvisoryRecord, VulnRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { parse as parseMalicious } from '../src/osv-malicious';
import { parseStix } from '../src/stix';

const ap = (id: string, extra: Record<string, unknown> = {}, source = 'mitre-attack') => ({
  type: 'attack-pattern',
  id: `attack-pattern--${id}`,
  name: `Technique ${id}`,
  modified: '2026-01-01T00:00:00.000Z',
  external_references: [{ source_name: source, external_id: id }],
  ...extra,
});
const bundle = (objects: unknown[]) => ({ type: 'bundle', id: 'bundle--1', objects });

describe('parseStix: ATT&CK sample', () => {
  const out = parseStix(fixture('mitre-attack', 'enterprise-sample.json'));
  it('keeps exactly the 4 live techniques', () => {
    expect(out.records.map((r) => r.id)).toEqual(['T1190', 'T1566', 'T1566.001', 'T1566.002']);
    expect(out.records.every((r) => r.framework === 'attack')).toBe(true);
    expect(out.version).toBe('20.1');
    expect(out.unknownFields).toEqual([]);
  });
  it('T1190 is a full record without citations or links', () => {
    const t = out.records.find((r) => r.id === 'T1190');
    expect(t).toEqual({
      id: 'T1190',
      framework: 'attack',
      name: 'Exploit Public-Facing Application',
      summary: expect.any(String),
    });
    expect(t?.summary?.length).toBeLessThanOrEqual(300);
    expect(t?.summary).not.toContain('(Citation:');
    expect(t?.summary).not.toContain('](');
  });
  it('sub-techniques get parents; revoked and deprecated are absent', () => {
    expect(out.records.find((r) => r.id === 'T1566.001')?.parent).toBe('T1566');
    expect(out.records.find((r) => r.id === 'T1566')?.parent).toBeUndefined();
    expect(out.records.some((r) => r.id === 'T1066' || r.id === 'T1153')).toBe(false);
  });
  it('every summary is at most 300 characters', () => {
    for (const r of out.records) expect((r.summary ?? '').length).toBeLessThanOrEqual(300);
  });
});

describe('parseStix: ATLAS sample', () => {
  const out = parseStix(fixture('mitre-atlas', 'stix-sample.json'));
  it('emits atlas techniques with parents', () => {
    expect(out.records.map((r) => r.id)).toEqual([
      'AML.T0000',
      'AML.T0000.000',
      'AML.T0051',
      'AML.T0051.000',
    ]);
    expect(out.records.every((r) => r.framework === 'atlas')).toBe(true);
    expect(out.records.map((r) => r.parent)).toEqual([undefined, 'AML.T0000', undefined, 'AML.T0051']);
    expect(out.version).toBe('2026.10');
    expect(out.unknownFields).toEqual(['type:x-example-new']);
  });
});

describe('parseStix: edge cases', () => {
  it('accepts a JSON string', () => {
    expect(parseStix(JSON.stringify(bundle([ap('T1190')]))).records).toHaveLength(1);
  });
  it('throws on a non-bundle and on bad JSON', () => {
    expect(() => parseStix({ type: 'identity' })).toThrow('stix: expected a STIX bundle');
    expect(() => parseStix(null)).toThrow('stix: expected a STIX bundle');
    expect(() => parseStix('{not json')).toThrow('stix: invalid JSON');
  });
  it('gives no parent when the parent is not in the bundle', () => {
    const r = parseStix(bundle([ap('T1566.001')])).records[0];
    expect(r).toBeDefined();
    expect(r?.parent).toBeUndefined();
  });
  it('keeps the later modified for duplicate ids, the later one on a tie', () => {
    const a = ap('T1190', { name: 'Old', modified: '2026-01-01T00:00:00.000Z' });
    const b = ap('T1190', { name: 'New', modified: '2026-02-01T00:00:00.000Z' });
    expect(parseStix(bundle([b, a])).records.map((r) => r.name)).toEqual(['New']);
    expect(parseStix(bundle([a, b])).records.map((r) => r.name)).toEqual(['New']);
    const c = ap('T1190', { name: 'Tie', modified: '2026-02-01T00:00:00.000Z' });
    expect(parseStix(bundle([b, c])).records.map((r) => r.name)).toEqual(['Tie']);
  });
  it('clips a 3,000-character description to 300', () => {
    const r = parseStix(bundle([ap('T1190', { description: 'word '.repeat(600) })])).records[0];
    expect(r?.summary?.length).toBeLessThanOrEqual(300);
    expect(r?.summary?.length).toBeGreaterThan(200);
  });
  it('strips citations, links and tags; omits an empty summary', () => {
    const d = 'Use <code>x</code> [a link](/techniques/T1) here.(Citation: Foo 2020)';
    expect(parseStix(bundle([ap('T1190', { description: d })])).records[0]?.summary).toBe(
      'Use x a link here.',
    );
    expect(
      parseStix(bundle([ap('T1190', { description: '(Citation: Foo)' })])).records[0],
    ).not.toHaveProperty('summary');
  });
  it('skips other-framework references, nameless and revoked objects', () => {
    const out = parseStix(
      bundle([
        ap('T1190', {}, 'mitre-mobile-attack'),
        ap('T1191', { name: '  ' }),
        ap('T1192', { revoked: true }),
        ap('T1193', { x_mitre_deprecated: true }),
      ]),
    );
    expect(out.records).toEqual([]);
  });
  it('throws on more than 5,000 techniques', () => {
    const many = (n: number) =>
      bundle(Array.from({ length: n }, (_, i) => ap(`T${String(i).padStart(4, '0')}`)));
    expect(parseStix(many(5000)).records).toHaveLength(5000);
    expect(() => parseStix(many(5001))).toThrow('stix: too many techniques');
  });
});

describe('osv-malicious', () => {
  it('the real record gives a mal vuln and an advisory', () => {
    const out = parseMalicious(fixture('openssf-malicious-packages', 'MAL-2026-12884.json'));
    expect(out.records).toHaveLength(2);
    const v = out.records.find((r) => 'key' in r) as VulnRecord;
    expect(v).toMatchObject({
      key: 'MAL-2026-12884',
      kind: 'mal',
      source: 'openssf-malicious-packages',
      cwe: ['CWE-506'],
    });
    const a = out.records.find((r) => 'sourceId' in r) as AdvisoryRecord;
    expect(a).toMatchObject({
      source: 'openssf-malicious-packages',
      sourceId: 'MAL-2026-12884',
      status: 'active',
    });
  });
  it('removed files, placeholders and non-MAL ids give nothing', () => {
    const text = fixture('openssf-malicious-packages', 'MAL-2026-12884.json');
    expect(
      parseMalicious({ path: 'osv/malicious/npm/x/MAL-2026-12884.json', status: 'removed', text: null })
        .records,
    ).toEqual([]);
    expect(
      parseMalicious(fixture('openssf-malicious-packages', 'MAL-0000-placeholder.json')).records,
    ).toEqual([]);
    expect(parseMalicious(fixture('github-advisory-db', 'GHSA-no-cve.json')).records).toEqual([]);
    expect(parseMalicious(text).records).toHaveLength(2);
  });
  it('a withdrawn file gives one withdrawn advisory and no vuln', () => {
    const out = parseMalicious(fixture('openssf-malicious-packages', 'withdrawn.json'));
    expect(out.records).toHaveLength(1);
    expect(out.records[0]).toMatchObject({ sourceId: 'MAL-2026-99999', status: 'withdrawn' });
    expect(out.records.some((r) => 'key' in r)).toBe(false);
  });
});
