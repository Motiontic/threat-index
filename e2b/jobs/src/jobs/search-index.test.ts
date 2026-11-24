import { resolvePrefix, searchShardKey } from '@ti/core/search';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { JobApi } from '../client.ts';
import type { Job, JobContext } from '../types.ts';
import {
  buildIndex,
  LETTER_PAGE_ITEMS,
  MAX_POSTINGS,
  MAX_SHARD_BYTES,
  MAX_SITEMAP_ENTRIES,
  run,
  type VulnRow,
} from './search-index.ts';

const BUILT = '2026-11-23T00:00:00.000Z';
const vuln = (key: string, title: string, extra: Record<string, unknown> = {}): VulnRow => ({
  key,
  kind: 'cve',
  title,
  summary: '',
  modified: '2026-11-01T10:00:00Z',
  hot: 1,
  ...extra,
});
const allTerms = (b: ReturnType<typeof buildIndex>) =>
  [...b.shards.values()].flatMap((s) => Object.keys(s.terms));

describe('buildIndex', () => {
  const vulns = [
    vuln('CVE-2024-1111', 'Apache Struts remote code execution', {
      summary: 'Struts lets attackers run code via OGNL',
      cwe: '["CWE-94"]',
      cvss: 9.8,
      kev_added: '2024-05-01',
      published: '2024-04-01',
    }),
    vuln('GHSA-aaaa-bbbb-cccc', 'Zebra parser overflow', { kind: 'ghsa' }),
    vuln('CVE-2024-2222', 'Rejected thing', {}),
    vuln('CVE-2024-3333', 'Cold row', { hot: 0 }),
    vuln('CVE-2024-4444', '9front kernel bug'),
    { key: 'CVE-2024-5555', hot: 1 }, // no title: skipped
  ];
  const advisories = [
    { source: 'nvd', source_id: 'CVE-2024-1111', vuln_key: 'CVE-2024-1111', status: 'active' },
    { source: 'ghsa', source_id: 'GHSA-aaaa-bbbb-cccc', vuln_key: 'GHSA-aaaa-bbbb-cccc', status: 'active' },
    { source: 'nvd', source_id: 'CVE-2024-2222', vuln_key: 'CVE-2024-2222', status: 'rejected' },
    { source: 'osv', source_id: 'OSV-2222', vuln_key: 'CVE-2024-2222', status: 'withdrawn' },
  ];
  const built = buildIndex(vulns, advisories, BUILT, { siteOrigin: 'https://ti.example' });

  it('puts terms in the right shard with sorted unique postings', () => {
    expect(built.shards.get('st')?.terms.struts).toEqual(['CVE-2024-1111']);
    expect(built.shards.get('ze')?.terms.zebra).toEqual(['GHSA-aaaa-bbbb-cccc']);
    expect(built.shards.get('cw')?.terms['cwe-94']).toEqual(['CVE-2024-1111']);
    expect(built.shards.get('st')?.builtAt).toBe(BUILT);
    expect(built.manifest).toEqual({ builtAt: BUILT, splits: [] });
    for (const [prefix, shard] of built.shards)
      for (const term of Object.keys(shard.terms)) expect(resolvePrefix(term, new Set())).toBe(prefix);
  });

  it('never indexes vuln keys or advisory ids as terms', () => {
    const terms = allTerms(built);
    for (const id of ['CVE-2024-1111', 'GHSA-aaaa-bbbb-cccc', 'OSV-2222', 'CVE-2024-4444'])
      expect(terms).not.toContain(id.toLowerCase());
    // The only `cv` term is the kind word, never an id.
    expect(Object.keys(built.shards.get('cv')?.terms ?? {})).toEqual(['cve']);
  });

  it('drops rejected-only and cold rows, and counts malformed ones', () => {
    expect(JSON.stringify([...built.shards.values()])).not.toContain('CVE-2024-2222');
    expect(JSON.stringify([...built.shards.values()])).not.toContain('CVE-2024-3333');
    expect(JSON.stringify([...built.letters.values()])).not.toContain('CVE-2024-2222');
    expect(built.sitemap).not.toContain('CVE-2024-2222');
    expect(built.stats.skipped).toBe(1);
    expect(built.stats.indexed).toBe(3);
  });

  it('writes docs with a trimmed summary and exploited flag', () => {
    const doc = built.shards.get('st')?.docs['CVE-2024-1111'];
    expect(doc).toMatchObject({ exploited: true, cvss: 9.8, published: '2024-04-01' });
    const long = buildIndex([vuln('X-1', 'Longword', { summary: 'a'.repeat(500) })], [], BUILT);
    expect(long.shards.get('lo')?.docs['X-1']?.summary).toHaveLength(160);
  });

  it('keeps the MAX_POSTINGS most recent entries of a term over the cap, marked truncated', () => {
    const many = Array.from({ length: MAX_POSTINGS + 50 }, (_, i) =>
      vuln(`K-${String(i).padStart(5, '0')}`, 'overflowing', {
        modified: `2026-01-01T00:00:00.${String(i).padStart(3, '0')}Z`,
      }),
    );
    const few = Array.from({ length: MAX_POSTINGS }, (_, i) => vuln(`J-${i}`, 'borderline'));
    const b = buildIndex([...many, ...few], [], BUILT);
    const ov = b.shards.get('ov');
    const list = ov?.terms.overflowing ?? [];
    expect(list).toHaveLength(MAX_POSTINGS);
    expect(list).toContain(`K-${String(MAX_POSTINGS + 49).padStart(5, '0')}`); // newest kept
    expect(list).not.toContain('K-00000'); // oldest dropped
    expect(ov?.truncated).toEqual(['overflowing']);
    expect(b.shards.get('bo')?.terms.borderline).toHaveLength(MAX_POSTINGS);
    expect(b.shards.get('bo')?.truncated).toBeUndefined();
    expect(b.shards.get('cv')?.truncated).toEqual(['cve']); // the shared kind word is over the cap too
    expect(b.stats.truncatedTerms).toBe(2);
    for (const shard of b.shards.values())
      for (const l of Object.values(shard.terms)) expect(l.length).toBeGreaterThan(0);
  });

  it('splits a prefix that does not fit into deeper shards listed in the manifest', () => {
    const rows: VulnRow[] = [];
    // 300 terms under `zz`, each shared by 1,990 rows (under the posting cap): about 8 MB of postings.
    const summary = Array.from({ length: 300 }, (_, i) => `zz${i}`).join(' ');
    for (let i = 0; i < 1990; i++)
      rows.push(vuln(`BIG-${String(i).padStart(6, '0')}`, 'bigdoc', { summary }));
    const b = buildIndex(rows, [], BUILT);
    expect(b.shards.has('zz')).toBe(false);
    expect(b.manifest.splits).toContain('zz');
    const splits = new Set(b.manifest.splits);
    for (let i = 0; i < 300; i++) {
      const term = `zz${i}`;
      const shard = b.shards.get(resolvePrefix(term, splits));
      expect(shard?.terms[term]).toHaveLength(1990);
      for (const k of shard?.terms[term] ?? []) expect(shard?.docs[k]).toBeDefined();
    }
    for (const shard of b.shards.values())
      expect(new TextEncoder().encode(JSON.stringify(shard)).length).toBeLessThanOrEqual(MAX_SHARD_BYTES);
  });

  it('fails instead of writing a shard it cannot fit', () => {
    // One term whose docs alone are over the cap: 1,500 rows, each with a 3 KB summary... capped at 160
    // chars, so use long keys instead.
    const rows = Array.from({ length: 1900 }, (_, i) => vuln(`${'k'.repeat(2000)}-${i}`, 'onlyterm'));
    expect(() => buildIndex(rows, [], BUILT)).toThrow(/cannot be split further/);
  });

  it('pages each letter at LETTER_PAGE_ITEMS, always with page 0', () => {
    const rows = Array.from({ length: 1203 }, (_, i) =>
      vuln(`A-${String(i).padStart(5, '0')}`, `alpha ${i}`),
    );
    const b = buildIndex(rows, [], BUILT);
    const pages = b.letters.get('a') ?? [];
    expect(pages.map((p) => p.items.length)).toEqual([500, 500, 203]);
    expect(pages.map((p) => p.cursor)).toEqual(['p1', 'p2', undefined]);
    expect(b.letters.get('q')).toEqual([{ letter: 'q', items: [] }]);
    expect(b.stats.largestLetterPageItems).toBe(LETTER_PAGE_ITEMS);
  });

  it('writes a sitemap with escaped values, and none without an origin', () => {
    expect(buildIndex(vulns, advisories, BUILT).sitemap).toBeNull();
    const b = buildIndex([vuln('A&B<1>', 'x1')], [], BUILT, { siteOrigin: 'https://ti.example' });
    expect(b.sitemap).toContain('<loc>https://ti.example/e/A%26B%3C1%3E</loc><lastmod>2026-11-01</lastmod>');
    expect(b.sitemap).toContain('<loc>https://ti.example/index/0</loc>');
    expect(b.sitemap).toContain('<loc>https://ti.example/sources</loc>');
    const esc = buildIndex([vuln("a'b", 'x1')], [], BUILT, { siteOrigin: 'https://ti.example/a&b' });
    expect(esc.sitemap).toContain('https://ti.example/a&amp;b/e/a&apos;b');
  });

  it('caps the sitemap at 49,000 entries, newest first', () => {
    const rows = Array.from({ length: MAX_SITEMAP_ENTRIES + 10 }, (_, i) =>
      vuln(`S-${i}`, 'sitemap row', { modified: `2026-01-01T00:00:${String(i % 60).padStart(2, '0')}Z` }),
    );
    rows.push(vuln('NEWEST', 'sitemap row', { modified: '2026-11-20T00:00:00Z' }));
    const b = buildIndex(rows, [], BUILT, { siteOrigin: 'https://ti.example' });
    const entries = (b.sitemap?.match(/\/e\//g) ?? []).length;
    expect(entries).toBe(MAX_SITEMAP_ENTRIES);
    expect(b.sitemap?.indexOf('/e/NEWEST')).toBeLessThan(b.sitemap?.indexOf('/e/S-') ?? 0);
  });
});

function fakeIo(
  vulns: VulnRow[],
  advisories: VulnRow[],
  opts: { refuse?: string; existing?: string[]; failDelete?: string } = {},
) {
  const deletes: string[] = [];
  const puts: { key: string; body: string; type: string }[] = [];
  const calls: { table: string; after: string | null; limit: number | undefined }[] = [];
  const api = {
    async rows(table: string, o: { after?: string; limit?: number } = {}) {
      calls.push({ table, after: o.after ?? null, limit: o.limit });
      const all = table === 'vulns' ? vulns : advisories;
      const start = o.after === undefined ? 0 : Number(o.after);
      const end = start + 2;
      return { rows: all.slice(start, end), next: end >= all.length ? null : String(end) };
    },
    async putObject(key: string, body: string | Uint8Array, type: string) {
      if (key === opts.refuse) throw new Error(`put-object refused: status 403`);
      puts.push({ key, body: String(body), type });
    },
    async *list(prefix: string) {
      for (const key of [...(opts.existing ?? []), ...puts.map((p) => p.key)])
        if (key.startsWith(prefix)) yield { key, size: 1 };
    },
    async deleteObject(key: string) {
      if (key === opts.failDelete) throw new Error('delete-object refused: status 500');
      deletes.push(key);
    },
  } as unknown as JobApi;
  return { api, puts, calls, deletes };
}
const job: Job = { id: 'job1', kind: 'search-index', apiBase: 'https://api.test', hmac: 'k' };
const ctx = (api: JobApi): JobContext & { logs: string[] } => {
  const logs: string[] = [];
  return { logs, api, log: (m) => void logs.push(m) };
};

describe('run', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('pages with next until null, uploads every key once, manifest last', async () => {
    vi.stubEnv('SITE_ORIGIN', 'https://ti.example');
    const vulns = ['alpha one', 'bravo two', 'charlie three', 'delta four', 'echo five'].map((t, i) =>
      vuln(`V-${i}`, t),
    );
    const { api, puts, calls } = fakeIo(vulns, []);
    await run(job, ctx(api));
    expect(calls.filter((c) => c.table === 'vulns').map((c) => c.after)).toEqual([null, '2', '4']);
    expect(calls.every((c) => c.limit === 1000)).toBe(true);
    expect(calls.at(-1)?.table).toBe('advisories');
    const keys = puts.map((p) => p.key);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys.filter((k) => k.startsWith('lookup/index/'))).toHaveLength(27);
    expect(keys).toContain('lookup/index/a/0.json');
    expect(keys).toContain('sitemap.xml');
    expect(keys).toContain(searchShardKey('al'));
    expect(keys.indexOf('lookup/search/v2/manifest.json')).toBeGreaterThan(
      keys.indexOf(searchShardKey('al')),
    );
    expect(keys.at(-1)).toBe('inbox/job1/manifest.json');
    expect(JSON.parse(puts.at(-1)?.body ?? '')).toMatchObject({ jobId: 'job1', chunks: [] });
    expect(puts.find((p) => p.key === 'sitemap.xml')?.type).toBe('application/xml');
    expect(puts.find((p) => p.key === searchShardKey('al'))?.type).toBe('application/json');
  });

  it('deletes old-layout objects after the build, keeps what it wrote, survives a failed delete', async () => {
    const existing = [
      'lookup/search/al.json', // old shard
      'lookup/search/zz.json',
      'lookup/index/a.json', // old letter file
      'lookup/search/v2/qq.json', // new layout, no longer written
      'lookup/index/a/7.json', // page beyond the new count
      searchShardKey('al'), // rewritten by this build
    ];
    const { api, puts, deletes } = fakeIo([vuln('V-1', 'alpha')], [], {
      existing,
      failDelete: 'lookup/search/zz.json',
    });
    await run(job, ctx(api));
    expect(deletes.sort()).toEqual(
      [
        'lookup/search/al.json',
        'lookup/index/a.json',
        'lookup/search/v2/qq.json',
        'lookup/index/a/7.json',
      ].sort(),
    );
    expect(deletes).not.toContain(searchShardKey('al'));
    expect(deletes).not.toContain('lookup/search/v2/manifest.json');
    expect(puts.at(-1)?.key).toBe('inbox/job1/manifest.json'); // job still completes
  });

  it('never deletes anything when the build fails', async () => {
    const { api, deletes } = fakeIo([vuln('V-1', 'alpha')], [], {
      existing: ['lookup/search/al.json'],
      refuse: 'lookup/index/a/0.json',
    });
    await expect(run(job, ctx(api))).rejects.toThrow(/refused/);
    expect(deletes).toEqual([]);
  });

  it('skips the sitemap without SITE_ORIGIN, with a log line', async () => {
    vi.stubEnv('SITE_ORIGIN', '');
    const { api, puts } = fakeIo([vuln('V-1', 'alpha')], []);
    const c = ctx(api);
    await run(job, c);
    expect(puts.map((p) => p.key)).not.toContain('sitemap.xml');
    expect(c.logs.some((l) => l.includes('sitemap skipped'))).toBe(true);
  });

  it('fails on a refused PUT and never writes the manifest', async () => {
    const { api, puts } = fakeIo([vuln('V-1', 'alpha')], [], { refuse: 'lookup/index/a/0.json' });
    await expect(run(job, ctx(api))).rejects.toThrow(/refused/);
    expect(puts.map((p) => p.key)).not.toContain('inbox/job1/manifest.json');
  });
});
