import { afterEach, describe, expect, it, vi } from 'vitest';
import type { JobApi } from '../client.ts';
import type { Job, JobContext } from '../types.ts';
import {
  buildIndex,
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
    for (const [prefix, shard] of built.shards)
      for (const term of Object.keys(shard.terms))
        expect(term.slice(0, 2).replace(/[^a-z0-9]/g, '_')).toBe(prefix);
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

  it('writes [] for a term over MAX_POSTINGS', () => {
    const many = Array.from({ length: MAX_POSTINGS + 1 }, (_, i) => vuln(`K-${i}`, 'overflowing'));
    const few = Array.from({ length: MAX_POSTINGS }, (_, i) => vuln(`J-${i}`, 'borderline'));
    const b = buildIndex([...many, ...few], [], BUILT);
    expect(b.shards.get('ov')?.terms.overflowing).toEqual([]);
    expect(b.shards.get('bo')?.terms.borderline).toHaveLength(MAX_POSTINGS);
    expect(b.shards.get('cv')?.terms.cve).toEqual([]); // the shared kind word is over the cap too
    expect(b.stats.trimmedTerms).toBe(2);
  });

  it('empties the largest lists until a shard fits MAX_SHARD_BYTES', () => {
    const rows: VulnRow[] = [];
    // 300 terms in shard `zz`, each shared by 1,990 rows (under the posting cap): about 8 MB of postings.
    const summary = Array.from({ length: 300 }, (_, i) => `zz${i}`).join(' ');
    for (let i = 0; i < 1990; i++)
      rows.push(vuln(`BIG-${String(i).padStart(6, '0')}`, 'bigdoc', { summary }));
    const b = buildIndex(rows, [], BUILT);
    const shard = b.shards.get('zz');
    expect(shard).toBeDefined();
    expect(new TextEncoder().encode(JSON.stringify(shard)).length).toBeLessThanOrEqual(MAX_SHARD_BYTES);
    expect(b.stats.trimmedTerms).toBeGreaterThan(0);
    // Every key in a remaining list has a doc.
    for (const list of Object.values(shard?.terms ?? {}))
      for (const k of list) expect(shard?.docs[k]).toBeDefined();
  });

  it('always has 27 letters, with digits under 0 and sorted items', () => {
    expect([...built.letters.keys()]).toHaveLength(27);
    expect(built.letters.get('0')?.items).toEqual([{ key: 'CVE-2024-4444', title: '9front kernel bug' }]);
    expect(built.letters.get('a')?.items).toEqual([
      { key: 'CVE-2024-1111', title: 'Apache Struts remote code execution' },
    ]);
    expect(built.letters.get('q')).toEqual({ letter: 'q', items: [] });
    const sorted = buildIndex([vuln('B-2', 'beta'), vuln('A-1', 'Beta'), vuln('C-3', 'alpha')], [], BUILT);
    expect(sorted.letters.get('b')?.items.map((i) => i.key)).toEqual(['A-1', 'B-2']);
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

function fakeIo(vulns: VulnRow[], advisories: VulnRow[], opts: { refuse?: string } = {}) {
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
  } as unknown as JobApi;
  return { api, puts, calls };
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
    expect(keys).toContain('sitemap.xml');
    expect(keys).toContain('lookup/search/al.json');
    expect(keys.at(-1)).toBe('inbox/job1/manifest.json');
    expect(JSON.parse(puts.at(-1)?.body ?? '')).toMatchObject({ jobId: 'job1', chunks: [] });
    expect(puts.find((p) => p.key === 'sitemap.xml')?.type).toBe('application/xml');
    expect(puts.find((p) => p.key === 'lookup/search/al.json')?.type).toBe('application/json');
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
    const { api, puts } = fakeIo([vuln('V-1', 'alpha')], [], { refuse: 'lookup/index/a.json' });
    await expect(run(job, ctx(api))).rejects.toThrow(/refused/);
    expect(puts.map((p) => p.key)).not.toContain('inbox/job1/manifest.json');
  });
});
