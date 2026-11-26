import type { AdvisoryRecord, ParsedRecord, ParseResult, VulnRecord } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check } from '../../patterns/src/changelist';
import { makeCtx, reply, route } from '../../patterns/test/helpers';
import { loadParser } from '../src/load';

const none = { records: [], unknownFields: [] };
const run = async (name: string, input: string) =>
  (await loadParser(name)).parse(input) as ParseResult<ParsedRecord>;
const adv = (r: unknown) =>
  (r as { records: AdvisoryRecord[] }).records.find((x) => 'sourceId' in x) as AdvisoryRecord;

describe('osv-ghsa', () => {
  it('GHSA-9x82-4j54-863h: a CVE alias, one advisory, a GitHub url', async () => {
    const out = await run('osv-ghsa', fixture('github-advisory-db', 'GHSA-9x82-4j54-863h.json'));
    expect(out.records).toHaveLength(1);
    expect(out.records[0]).toEqual({
      source: 'github-advisory-db',
      sourceId: 'GHSA-9x82-4j54-863h',
      vulnKey: 'CVE-2026-63476',
      status: 'active',
      published: '2026-11-23T21:07:02.000Z',
      modified: '2026-11-23T21:07:02.000Z',
      url: 'https://github.com/advisories/GHSA-9x82-4j54-863h',
      affected: [{ ecosystem: 'npm', name: 'isomorphic-git', fixed: '1.38.6', rangeType: 'ECOSYSTEM' }],
      summary: expect.stringContaining('isomorphic-git'),
      severity: 'MODERATE',
      reviewed: true,
    });
  });

  it('GHSA-no-cve: a ghsa vuln with unique valid CWEs', async () => {
    const out = await run('osv-ghsa', fixture('github-advisory-db', 'GHSA-no-cve.json'));
    expect(out.records).toHaveLength(2);
    const v = out.records.find((x) => 'key' in x) as VulnRecord;
    expect(v).toMatchObject({
      key: 'GHSA-aaaa-bbbb-cccc',
      kind: 'ghsa',
      cwe: ['CWE-79'],
      aliases: [],
      source: 'github-advisory-db',
    });
    expect(adv(out)).toMatchObject({
      vulnKey: null,
      affected: [{ ecosystem: 'npm', name: 'example-pkg', fixed: '3.1.0' }],
    });
  });

  it('skips non-GHSA ids', async () => {
    expect(await run('osv-ghsa', fixture('osv', 'GO-2026-5006.json'))).toEqual(none);
  });
});

describe('osv-debian', () => {
  it('per-CVE record: CVE from upstream, bare-range packages fall back to versions', async () => {
    const out = await run('osv-debian', fixture('debian', 'DEBIAN-CVE-2026-97845.json'));
    expect(out.records).toHaveLength(1);
    const a = adv(out);
    expect(a).toMatchObject({
      source: 'debian',
      sourceId: 'DEBIAN-CVE-2026-97845',
      vulnKey: 'CVE-2026-97845',
      status: 'active',
      published: '2026-11-12T14:17:30.880Z',
      modified: '2026-11-23T21:01:36.243Z',
      url: 'https://security-tracker.debian.org/tracker/CVE-2026-97845',
    });
    expect(a.affected?.length).toBe(6);
    expect(a.affected?.slice(0, 3)).toEqual(
      ['Debian:12', 'Debian:13', 'Debian:14'].map((ecosystem) => ({
        ecosystem,
        name: 'qt6-5compat',
        rangeType: 'ECOSYSTEM',
      })),
    );
    expect(a.reviewed).toBe(true);
    expect(a.severity).toBeUndefined();
  });

  it('skips DSA notices', async () => {
    expect(await run('osv-debian', fixture('debian', 'DSA-6654-1.json'))).toEqual(none);
  });
});

describe('osv-ubuntu', () => {
  it('per-CVE record trimmed to 3 affected entries', async () => {
    const out = await run('osv-ubuntu', fixture('ubuntu', 'UBUNTU-CVE-2026-99315.json'));
    expect(out.records).toHaveLength(1);
    const a = adv(out);
    expect(a).toMatchObject({
      source: 'ubuntu',
      sourceId: 'UBUNTU-CVE-2026-99315',
      vulnKey: 'CVE-2026-99315',
      status: 'active',
      published: '2026-11-19T00:00:00.000Z',
      modified: '2026-11-20T06:34:52.097Z',
      url: 'https://osv.dev/vulnerability/UBUNTU-CVE-2026-99315',
    });
    expect(a.affected?.map((x) => x.name)).toEqual(['linux', 'linux-aws', 'linux-azure']);
    expect(a.affected?.[0]?.ecosystem).toBe('Ubuntu:Pro:14.04:LTS');
    expect(a.affected?.length).toBeLessThanOrEqual(200);
    expect(a.severity).toBe('MEDIUM');
    expect(a.reviewed).toBe(true);
  });

  it('skips USN notices', async () => {
    expect(await run('osv-ubuntu', fixture('ubuntu', 'USN-9176-1.json'))).toEqual(none);
  });
});

describe('the four sources', () => {
  const LICENCE = { osv: 'on', 'github-advisory-db': 'on', debian: 'ask', ubuntu: 'ask' } as const;
  const HOST = 'https://osv-vulnerabilities.storage.googleapis.com';
  const PARSER = { osv: 'osv', 'github-advisory-db': 'osv-ghsa', debian: 'osv-debian', ubuntu: 'osv-ubuntu' };

  for (const [id, licence] of Object.entries(LICENCE)) {
    it(`${id}: parser loads, pull matches the pattern, licence is ${licence}`, async () => {
      const s = SOURCE_BY_ID.get(id);
      expect(s?.licence).toBe(licence);
      expect(s?.parser).toBe(PARSER[id as keyof typeof PARSER]);
      expect(typeof (await loadParser(s?.parser as string)).parse).toBe('function');
      if (s?.pattern === 'git') {
        expect(s.pull?.git).toEqual({
          repo: 'github/advisory-database',
          branch: 'main',
          include: ['advisories/github-reviewed/**/*.json'],
        });
      } else {
        const dir = id === 'osv' ? '' : `${id === 'debian' ? 'Debian' : 'Ubuntu'}/`;
        expect(s?.pull?.changelist).toEqual({
          listUrl: `${HOST}/${dir}modified_id.csv`,
          timeColumn: 0,
          refColumn: 1,
          itemUrl: `${HOST}/${dir}{ref}.json`,
        });
      }
    });
  }

  it('debian: the changelist check answers unchanged on a 304', async () => {
    const source = SOURCE_BY_ID.get('debian');
    if (!source) throw new Error('no debian source');
    const h = makeCtx({
      source,
      cursor: { kind: 'timestamp', value: JSON.stringify(['2026-11-23T20:00:00Z', 'DSA-1']), etag: '"v1"' },
      routes: [route(`${HOST}/Debian/modified_id.csv`, reply(null, 304), 'HEAD')],
    });
    expect(await check(h.ctx)).toBe('unchanged');
    expect(h.requests[0]?.headers['if-none-match']).toBe('"v1"');
  });
});

describe('other parsers give no package entries', () => {
  it('NVD, CSAF and CERT/CC fixtures have no rangeType', async () => {
    const cases: [string, string, string][] = [
      ['nvd', 'nvd', 'CVE-2024-3400.json'],
      ['csaf', 'red-hat', 'cve-2023-38545.json'],
      ['cert-cc', 'cert-cc', 'note-604762.json'],
    ];
    for (const [parser, dir, file] of cases) {
      const out = await run(parser, fixture(dir, file));
      for (const r of out.records) {
        if ('sourceId' in r)
          for (const a of r.affected ?? []) expect(a.rangeType, `${parser} ${a.name}`).toBeUndefined();
      }
    }
  });
});
