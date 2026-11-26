import type { AdvisoryRecord, VulnRecord } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { loadParser } from '../src/load';
import { LANGUAGE_ECOSYSTEMS, MAX_AFFECTED, parse, parseOsv, reviewedFix } from '../src/osv';

const go = fixture('osv', 'GO-2026-5006.json');
const mal = fixture('osv', 'MAL-2026-12900.json');
const noCve = fixture('osv', 'no-cve.json');
const withdrawn = fixture('osv', 'withdrawn.json');
const bad = fixture('osv', 'bad.json');

const PKG = { package: { ecosystem: 'PyPI', name: 'p' } };
const advisory = (r: { records: unknown[] }) =>
  r.records.find((x) => 'sourceId' in (x as object)) as AdvisoryRecord;
const vuln = (r: { records: unknown[] }) => r.records.find((x) => 'key' in (x as object)) as VulnRecord;

describe('osv parser', () => {
  it('GO-2026-5006: a CVE alias makes one advisory and no vuln', () => {
    const out = parse(go);
    expect(out.records).toHaveLength(1);
    expect(out.records[0]).toEqual({
      source: 'osv',
      sourceId: 'GO-2026-5006',
      vulnKey: 'CVE-2026-39832',
      status: 'active',
      published: '2026-05-22T02:08:34.000Z',
      modified: '2026-11-23T21:12:30.200Z',
      url: 'https://osv.dev/vulnerability/GO-2026-5006',
      affected: [{ ecosystem: 'Go', name: 'golang.org/x/crypto', fixed: '0.52.0', rangeType: 'SEMVER' }],
      reviewed: true,
      summary: expect.any(String),
    });
    expect(out.unknownFields).toEqual([]);
  });

  it('MAL-2026-12900: no CVE gives a vuln of kind mal, and a version-list advisory', () => {
    const out = parse(mal);
    expect(out.records).toHaveLength(2);
    const v = vuln(out);
    expect(v).toMatchObject({
      key: 'MAL-2026-12900',
      kind: 'mal',
      title: 'Malicious code in bnpl-blocks-atom-container (npm)',
      aliases: ['GHSA-75c2-xxw8-hccv'],
      cwe: ['CWE-506'],
      source: 'osv',
      modified: '2026-11-23T20:30:04.607Z',
      published: '2026-08-05T14:53:33.000Z',
    });
    expect(v.summary).toBe(v.title);
    const a = advisory(out);
    expect(a.vulnKey).toBeNull();
    expect(a.affected).toEqual([
      { ecosystem: 'npm', name: 'bnpl-blocks-atom-container', rangeType: 'SEMVER' },
    ]);
    expect(a.reviewed).toBe(false);
  });

  it('no-cve.json: pairs, last_affected, GIT skipped, unknown field named', () => {
    const out = parse(noCve);
    expect(out.records).toHaveLength(2);
    const v = vuln(out);
    expect(v).toMatchObject({
      key: 'RUSTSEC-2026-0001',
      kind: 'osv',
      title: 'Hand-written: out-of-bounds read in example-crate',
      aliases: [],
      cwe: [],
    });
    const a = advisory(out);
    expect(a).toMatchObject({
      vulnKey: null,
      status: 'active',
      published: '2026-11-01T08:30:00.000Z',
      modified: '2026-11-20T10:00:00.123Z',
      url: 'https://osv.dev/vulnerability/RUSTSEC-2026-0001',
    });
    const e = { ecosystem: 'crates.io', name: 'example-crate', rangeType: 'SEMVER' };
    expect(a.affected).toEqual([
      { ...e, introduced: '0.1.0', fixed: '0.1.5' },
      { ...e, introduced: '0.2.0', fixed: '0.2.3' },
      { ...e, introduced: '1.0.0', range: '<= 1.0.4', lastAffected: '1.0.4' },
    ]);
    expect(out.unknownFields).toEqual(['newTopLevelField']);
  });

  it('withdrawn.json: a withdrawn advisory, no vuln', () => {
    const out = parse(withdrawn);
    expect(out.records).toHaveLength(1);
    expect(advisory(out)).toMatchObject({ status: 'withdrawn', vulnKey: 'CVE-2026-0001' });
  });

  it('first ADVISORY reference becomes the url; a lone introduced 0 is a bare entry', () => {
    const out = parse({
      id: 'GO-1',
      modified: '2026-01-01T00:00:00Z',
      references: [
        { type: 'WEB', url: 'https://example.invalid/web' },
        { type: 'ADVISORY', url: 'javascript:alert(1)' },
        { type: 'ADVISORY', url: 'https://example.invalid/adv' },
      ],
      affected: [
        {
          package: { ecosystem: 'Go', name: 'x' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
        },
      ],
    });
    expect(advisory(out).url).toBe('https://example.invalid/adv');
    expect(advisory(out).affected).toEqual([{ ecosystem: 'Go', name: 'x', rangeType: 'SEMVER' }]);
  });

  it('cuts long version lists and long text, drops duplicates', () => {
    const versions = Array.from({ length: 25 }, (_, i) => `1.${i}`);
    const out = parse({
      id: 'PYSEC-1',
      modified: '2026-01-01T00:00:00Z',
      summary: 'x'.repeat(250),
      details: 'y'.repeat(500),
      affected: [
        { package: { ecosystem: 'PyPI', name: 'p' }, versions },
        { package: { ecosystem: 'PyPI', name: 'p' }, versions },
      ],
    });
    const a = advisory(out);
    expect(a.affected).toHaveLength(1);
    expect(a.affected?.[0]?.range?.endsWith('1.19 (+5 more)')).toBe(true);
    const long = parse({
      id: 'PYSEC-2',
      modified: '2026-01-01T00:00:00Z',
      affected: [PKG],
      details: `${'word '.repeat(100)}\nsecond`,
    });
    expect(vuln(long).summary).toHaveLength(300);
    expect(vuln(long).summary.endsWith('…')).toBe(true);
    expect(vuln(long).title).toHaveLength(200);
  });

  it('keeps at most MAX_AFFECTED entries, in input order', () => {
    const affected = Array.from({ length: 300 }, (_, i) => ({
      package: { ecosystem: 'npm', name: `p${i}` },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
    }));
    const a = advisory(
      parse({ id: 'PYSEC-3', modified: '2026-01-01T00:00:00Z', aliases: ['CVE-2026-1111'], affected }),
    );
    expect(a.affected).toHaveLength(MAX_AFFECTED);
    expect(a.affected?.[0]?.name).toBe('p0');
    expect(a.affected?.[MAX_AFFECTED - 1]?.name).toBe(`p${MAX_AFFECTED - 1}`);
  });

  it('truncates nine-digit fractions and converts offsets to UTC', () => {
    const a = advisory(
      parse({
        id: 'PYSEC-4',
        modified: '2026-01-01T01:00:00.999999999+01:00',
        published: 'nope',
        affected: [PKG],
      }),
    );
    expect(a.modified).toBe('2026-01-01T00:00:00.999Z');
    expect(a.published).toBeUndefined();
  });

  it('gives equal output for a ChangeItem, a GitFile, a string and an object', () => {
    const expected = parse(JSON.parse(go));
    expect(parse(go)).toEqual(expected);
    expect(parse({ ref: 'Go/GO-2026-5006', time: '2026-11-23T21:12:30.2Z', text: go })).toEqual(expected);
    expect(parse({ path: 'x/GO-2026-5006.json', status: 'modified', text: go })).toEqual(expected);
  });

  it('gives no records for null text, removed files, dropped ecosystems and GHSA ids', () => {
    const none = { records: [], unknownFields: [] };
    expect(parse({ ref: 'Go/GO-1', time: 't', text: null })).toEqual(none);
    expect(parse({ path: 'a.json', status: 'removed', text: go })).toEqual(none);
    const redhat = JSON.stringify({
      id: 'RHSA-2026:1',
      modified: '2026-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'Red Hat:enterprise_linux:9', name: 'x' } }],
    });
    expect(parse({ ref: 'Red Hat/RHSA-2026:1', time: 't', text: redhat })).toEqual(none);
    expect(parse(redhat)).toEqual(none);
    // Mixed ecosystems are dropped, as are ecosystem-less records.
    const mixed = {
      id: 'X-1',
      modified: '2026-01-01T00:00:00Z',
      affected: [
        { package: { ecosystem: 'npm', name: 'a' } },
        { package: { ecosystem: 'Alpine:v3.20', name: 'a' } },
      ],
    };
    expect(parse(mixed)).toEqual(none);
    expect(parse({ id: 'X-2', modified: '2026-01-01T00:00:00Z' })).toEqual(none);
    const ghsa = {
      id: 'GHSA-aaaa-bbbb-cccc',
      modified: '2026-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'a' } }],
    };
    expect(parse(ghsa)).toEqual(none);
  });

  it('uses the ChangeItem ref prefix as an ecosystem', () => {
    const rec = JSON.stringify({
      id: 'X-3',
      modified: '2026-01-01T00:00:00Z',
      affected: [{ package: { ecosystem: 'npm', name: 'a' } }],
    });
    expect(parse({ ref: 'Docker Hardened Images/X-3', time: 't', text: rec }).records).toEqual([]);
    expect(parse({ ref: 'npm/X-3', time: 't', text: rec }).records).toHaveLength(2);
  });

  it('throws on bad input', () => {
    expect(() => parse(bad)).toThrow();
    expect(() => parse('{not json')).toThrow('invalid JSON');
    expect(() => parse(42)).toThrow();
    expect(() => parse([])).toThrow();
    expect(() => parse({ id: '../etc', modified: '2026-01-01T00:00:00Z' })).toThrow('unsafe id');
    expect(() => parse({ id: 'A-1' })).toThrow('modified');
    expect(() => parse({ id: 'A-1', modified: 'yesterday' })).toThrow('modified');
  });

  it('lists unknown fields by name and never looks inside database_specific', () => {
    const out = parse({
      id: 'PYSEC-5',
      modified: '2026-01-01T00:00:00Z',
      top: 1,
      database_specific: { whatever: 1 },
      affected: [
        {
          package: { ecosystem: 'PyPI', name: 'p' },
          extra: 1,
          ecosystem_specific: { more: 1 },
          ranges: [{ type: 'ECOSYSTEM', extraRange: 1, events: [{ introduced: '0', extraEvent: 1 }] }],
        },
      ],
    });
    expect(out.unknownFields.sort()).toEqual(
      ['top', 'affected.extra', 'affected.ranges.extraRange', 'affected.ranges.events.extraEvent'].sort(),
    );
  });

  it('a profile decides which records are kept and names the source', () => {
    const out = parseOsv(go, { source: 'custom', keep: () => true });
    expect(advisory(out).source).toBe('custom');
    expect(parseOsv(go, { source: 'custom', keep: () => false }).records).toEqual([]);
    expect(LANGUAGE_ECOSYSTEMS.has('npm')).toBe(true);
    expect(LANGUAGE_ECOSYSTEMS.has('Debian')).toBe(false);
  });
});

describe('osv parser: package data', () => {
  const rec = (affected: unknown[], extra: object = {}) =>
    parse({ id: 'PYSEC-9', modified: '2026-01-01T00:00:00Z', aliases: ['CVE-2026-1'], affected, ...extra });

  it('GO-2026-5006 is reviewed; UNREVIEWED is not', () => {
    const doc = JSON.parse(go);
    expect(advisory(parse(doc)).reviewed).toBe(true);
    doc.database_specific = { ...doc.database_specific, review_status: 'UNREVIEWED' };
    expect(advisory(parse(doc)).reviewed).toBe(false);
  });

  it('MAL-2026-12884 means every version: one bare SEMVER entry, no EXACT', async () => {
    const malicious = await loadParser('osv-malicious');
    const a = advisory(
      malicious.parse(fixture('openssf-malicious-packages', 'MAL-2026-12884.json')) as never,
    );
    expect(a.affected).toHaveLength(1);
    expect(a.affected?.[0]).toMatchObject({ rangeType: 'SEMVER' });
    expect(a.affected?.[0]).not.toHaveProperty('introduced');
    expect(a.affected?.[0]).not.toHaveProperty('versions');
    expect(a.reviewed).toBe(false);
  });

  it('last_affected is data and display text; two ranges and two pairs in one range', () => {
    const a = advisory(
      rec([
        {
          package: PKG.package,
          ranges: [
            {
              type: 'ECOSYSTEM',
              events: [{ introduced: '1' }, { fixed: '2' }, { introduced: '3' }, { last_affected: '3.5' }],
            },
            { type: 'SEMVER', events: [{ introduced: '5' }, { fixed: '6' }, { limit: '9' }] },
          ],
        },
      ]),
    );
    const e = { ecosystem: 'PyPI', name: 'p' };
    expect(a.affected).toEqual([
      { ...e, rangeType: 'ECOSYSTEM', introduced: '1', fixed: '2' },
      { ...e, rangeType: 'ECOSYSTEM', introduced: '3', range: '<= 3.5', lastAffected: '3.5' },
      { ...e, rangeType: 'SEMVER', introduced: '5', fixed: '6' },
    ]);
  });

  it('a GIT-only entry gives nothing', () => {
    const a = advisory(
      rec([{ package: PKG.package, ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }] }] }]),
    );
    expect(a.affected).toEqual([]);
  });

  it('a versions-only entry becomes EXACT with every version; a range next to a list wins', () => {
    const versions = Array.from({ length: 25 }, (_, i) => `1.${i}`);
    const a = advisory(rec([{ package: PKG.package, versions }]));
    expect(a.affected?.[0]).toMatchObject({ rangeType: 'EXACT', versions });
    const b = advisory(
      rec([
        {
          package: PKG.package,
          versions,
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2' }] }],
        },
      ]),
    );
    expect(b.affected).toEqual([{ ecosystem: 'PyPI', name: 'p', rangeType: 'ECOSYSTEM', fixed: '2' }]);
  });

  it('1,001 versions keep only the display entry', () => {
    const versions = Array.from({ length: 1001 }, (_, i) => `1.${i}`);
    const a = advisory(rec([{ package: PKG.package, versions }]));
    expect(a.affected).toHaveLength(1);
    expect(a.affected?.[0]).not.toHaveProperty('rangeType');
    expect(a.affected?.[0]).not.toHaveProperty('versions');
    expect(a.affected?.[0]?.range).toContain('(+981 more)');
  });

  it('a withdrawn record keeps its entries', () => {
    const a = advisory(
      rec(
        [
          {
            package: PKG.package,
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2' }] }],
          },
        ],
        {
          withdrawn: '2026-02-01T00:00:00Z',
        },
      ),
    );
    expect(a.status).toBe('withdrawn');
    expect(a.affected).toHaveLength(1);
  });

  it('summary and severity', () => {
    const a = advisory(rec([PKG], { summary: '  a   b ', database_specific: { severity: 'moderate' } }));
    expect(a.summary).toBe('a b');
    expect(a.severity).toBe('MODERATE');
    const b = advisory(
      rec([PKG], {
        database_specific: { severity: 'two words' },
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }],
      }),
    );
    expect(b.severity).toBeUndefined();
    const c = advisory(rec([PKG], { severity: [{ type: 'Ubuntu', score: 'medium' }] }));
    expect(c.severity).toBe('MEDIUM');
  });

  it('reviewedFix follows the table', () => {
    const rows: [string, string, Record<string, unknown>, boolean][] = [
      ['github-advisory-db', 'GHSA-1', { github_reviewed: true }, true],
      ['github-advisory-db', 'GHSA-1', { github_reviewed: false }, false],
      ['github-advisory-db', 'GHSA-1', {}, false],
      ['osv', 'PYSEC-1', {}, true],
      ['osv', 'RUSTSEC-1', {}, true],
      ['osv', 'GO-1', { review_status: 'REVIEWED' }, true],
      ['osv', 'GO-1', { review_status: 'UNREVIEWED' }, false],
      ['osv', 'GO-1', {}, false],
      ['osv', 'MAL-1', {}, false],
      ['osv', 'HSEC-1', {}, false],
      ['debian', 'DEBIAN-CVE-1', {}, true],
      ['ubuntu', 'UBUNTU-CVE-1', {}, true],
      ['openssf-malicious-packages', 'MAL-1', {}, false],
      ['openssf-malicious-packages', 'PYSEC-1', {}, false],
      ['cve-list', 'CVE-1', {}, false],
    ];
    for (const [source, id, db, want] of rows)
      expect(reviewedFix(source, id, db), `${source} ${id}`).toBe(want);
  });
});
