import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCES } from '@ti/sources/registry';
import { beforeAll, describe, expect, it } from 'vitest';

// Signed-in requests: `vi.mock('@hono/clerk-auth')` does not take effect in this Workers pool (the real
// middleware still ran), so the route modules are mounted on a test app with a stub middleware instead.
// It sets the same `clerkAuth` variable the real getAuth reads, and signs in only with the test header.
const { Hono } = await import('hono');
const { default: entries } = await import('../src/routes/entries');
const { default: indexLetter } = await import('../src/routes/index-letter');
const { default: sources } = await import('../src/routes/sources');
const app = new Hono();
app.use('/v1/*', async (c, next) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
  await next();
});
for (const r of [entries, indexLetter, sources]) app.route('/', r as never);
const { decodeUlidTime } = await import('../src/routes/entries');

const E = env as unknown as {
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_SIGNALS: D1Database;
  DB_CONTROL: D1Database;
  BUCKET: R2Bucket;
  SETTINGS: KVNamespace;
};

async function get(path: string, opts: { user?: boolean; env?: object } = {}) {
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(`https://api.test${path}`, opts.user ? { headers: { 'x-test-user': 'user_1' } } : undefined),
    (opts.env ?? env) as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}

const json = async (res: Response) => (await res.json()) as any;

async function vuln(key: string, o: Record<string, unknown> = {}) {
  const r = {
    kind: 'cve',
    title: `Title ${key}`,
    summary: 'Sum',
    published: '2025-01-01',
    modified: '2025-01-02T00:00:00Z',
    cvss: 7.5,
    cvss_version: '3.1',
    cvss_source: 'nvd',
    cwe: '["CWE-79"]',
    kev_added: null,
    ransomware: 0,
    epss: 0.5,
    sources: '["nvd"]',
    doc_key: 'docs/secret',
    ...o,
  };
  await E.DB_VULNS.prepare(
    `INSERT OR REPLACE INTO vulns (key, kind, title, summary, published, modified, cvss, cvss_version, cvss_source, cwe, kev_added, ransomware, epss, sources, doc_key)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)`,
  )
    .bind(
      key,
      r.kind,
      r.title,
      r.summary,
      r.published,
      r.modified,
      r.cvss,
      r.cvss_version,
      r.cvss_source,
      r.cwe,
      r.kev_added,
      r.ransomware,
      r.epss,
      r.sources,
      r.doc_key,
    )
    .run();
}
async function adv(
  source: string,
  sourceId: string,
  vulnKey: string | null,
  extra: { url?: string; modified?: string } = {},
) {
  await E.DB_ADVISORIES.prepare(
    "INSERT OR REPLACE INTO advisories (source, source_id, vuln_key, status, published, modified, url) VALUES (?1,?2,?3,'active','2025-02-01',?4,?5)",
  )
    .bind(
      source,
      sourceId,
      vulnKey,
      extra.modified ?? '2025-02-02T00:00:00Z',
      extra.url ?? 'https://example.test/a',
    )
    .run();
}
async function signal(key: string, kind: string, source: string, ref: string, firstSeen = '2025-03-01') {
  await E.DB_SIGNALS.prepare(
    'INSERT INTO signals (vuln_key, kind, source, ref, first_seen, url) VALUES (?1,?2,?3,?4,?5,?6)',
  )
    .bind(key, kind, source, ref, firstSeen, 'https://example.test/s')
    .run();
}
async function change(id: string, key: string, at: string, source: string | null = 'nvd') {
  await E.DB_SIGNALS.prepare(
    "INSERT INTO changes (id, entity_key, kind, old, new, at, source) VALUES (?1,?2,'cvss_change','5','9',?3,?4)",
  )
    .bind(id, key, at, source)
    .run();
}

const PREVIEW_KEYS = [
  'aliases',
  'credits',
  'cvss',
  'cvssVersion',
  'epss',
  'exploited',
  'key',
  'kind',
  'modified',
  'published',
  'summary',
  'title',
];

describe('1. preview', () => {
  it('visitor gets exactly the camelCase EntryPreview keys', async () => {
    await vuln('CVE-2030-0001');
    const res = await get('/v1/entries/CVE-2030-0001');
    const body = await json(res);
    expect(body.access).toBe('preview');
    expect(Object.keys(body.entry).sort()).toEqual(PREVIEW_KEYS);
    expect(body.entry.exploited).toBe(false);
    for (const k of ['cwe', 'advisories', 'signals', 'changes', 'doc_key'])
      expect(body.entry).not.toHaveProperty(k);
    expect(body.entry.cvssVersion).toBe('3.1');
  });
  it('exploited: KEV, visible exploited_wild signal; not a wait source', async () => {
    await vuln('CVE-2030-0002', { kev_added: '2025-05-05', kind: 'cve' });
    expect((await json(await get('/v1/entries/CVE-2030-0002'))).entry.exploited).toBe(true);
    expect((await json(await get('/v1/entries/CVE-2030-0002'))).entry.kevAdded).toBe('2025-05-05');
    await vuln('CVE-2030-0003');
    await signal('CVE-2030-0003', 'exploited_wild', 'cisa-kev', 'r');
    expect((await json(await get('/v1/entries/CVE-2030-0003'))).entry.exploited).toBe(true);
    await vuln('CVE-2030-0004');
    await signal('CVE-2030-0004', 'exploited_wild', 'vulncheck', 'r');
    expect((await json(await get('/v1/entries/CVE-2030-0004'))).entry.exploited).toBe(false);
  });
});

describe('2. full', () => {
  it('signed-in gets cwe, advisories, separate signals, recent changes newest first', async () => {
    const k = 'CVE-2030-0010';
    await vuln(k, { cwe: '["CWE-79","CWE-20"]' });
    await adv('osv', 'PYSEC-2030-1', k);
    await adv('github-advisory-db', 'GHSA-aaaa-bbbb-cccc', k);
    await signal(k, 'public_exploit', 'metasploit', 'm1', '2025-03-02');
    await signal(k, 'exploited_wild', 'cisa-kev', 'k1', '2025-03-03');
    const now = Date.now();
    await change('c-new', k, new Date(now - 86400000).toISOString());
    await change('c-newer', k, new Date(now - 3600000).toISOString());
    await change('c-old', k, new Date(now - 100 * 86400000).toISOString());
    const res = await get(`/v1/entries/${k}`, { user: true });
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    const { access, entry } = await json(res);
    expect(access).toBe('full');
    expect(entry.cwe).toEqual(['CWE-79', 'CWE-20']);
    expect(entry.advisories.map((a: any) => a.source)).toEqual(['github-advisory-db', 'osv']);
    expect(entry.signals.map((s: any) => s.kind)).toEqual(['exploited_wild', 'public_exploit']);
    expect(entry.changes).toHaveLength(2);
    expect(entry.changes[0].at > entry.changes[1].at).toBe(true);
    expect(entry.aliases).toEqual(['GHSA-aaaa-bbbb-cccc', 'PYSEC-2030-1']);
  });
  it('bad cwe JSON gives []', async () => {
    await vuln('CVE-2030-0011', { cwe: '{nope' });
    expect((await json(await get('/v1/entries/CVE-2030-0011', { user: true }))).entry.cwe).toEqual([]);
    await vuln('CVE-2030-0012', { cwe: '[1,2]' });
    expect((await json(await get('/v1/entries/CVE-2030-0012', { user: true }))).entry.cwe).toEqual([]);
  });
});

describe('3. aliases', () => {
  it('resolves lowercase CVE, GHSA via prefix map, alias rows, and rejects bad ids', async () => {
    const k = 'CVE-2030-0020';
    await vuln(k);
    await adv('github-advisory-db', 'GHSA-xxxx-xxxx-xxxx'.replace(/x/g, 'c'), k);
    await adv('alias', 'EUVD-2030-1', k);
    await adv('alias', 'some.alias_1', k);
    expect((await json(await get('/v1/entries/cve-2030-0020'))).entry.key).toBe(k);
    expect((await json(await get('/v1/entries/GHSA-CCCC-Cccc-cccc'))).entry.key).toBe(k);
    expect((await json(await get('/v1/entries/EUVD-2030-1'))).entry.key).toBe(k);
    expect((await json(await get('/v1/entries/some.alias_1'))).entry.key).toBe(k);
    const miss = await get('/v1/entries/CVE-1999-0000');
    expect(miss.status).toBe(404);
    expect(await json(miss)).toEqual({ error: 'not_found' });
    const long = await get(`/v1/entries/${'a'.repeat(200)}`);
    expect(long.status).toBe(400);
    expect(await json(long)).toEqual({ error: 'bad_id' });
    expect((await get('/v1/entries/a%2Fb')).status).toBe(400);
  });
  it('an alias row pointing to a missing vuln is 404', async () => {
    await adv('alias', 'ghost-1', 'CVE-2030-9999');
    expect((await get('/v1/entries/ghost-1')).status).toBe(404);
  });
});

describe('4. licence', () => {
  it('link source keeps only link fields; wait source is absent everywhere', async () => {
    const k = 'CVE-2030-0030';
    await vuln(k, { sources: '["nvd","zdi","vulncheck"]' });
    await adv('zdi', 'ZDI-30-1', k);
    await adv('vulncheck', 'VC-30-1', k);
    await signal(k, 'poc', 'vulncheck', 'x');
    await signal(k, 'poc', 'metasploit', 'y');
    const { entry } = await json(await get(`/v1/entries/${k}`, { user: true }));
    const zdi = entry.advisories.find((a: any) => a.source === 'zdi');
    expect(Object.keys(zdi).sort()).toEqual(['display', 'published', 'source', 'sourceId', 'status', 'url']);
    expect(zdi.display).toBe('link');
    expect(JSON.stringify(entry)).not.toContain('vulncheck');
    expect(JSON.stringify(entry)).not.toContain('VC-30-1');
    expect(entry.aliases).toEqual(['ZDI-30-1']);
    expect(entry.signals.map((s: any) => s.source)).toEqual(['metasploit']);
  });
  it('KV overrides hide or downgrade; malformed KV is ignored; hidden cvss_source drops cvss', async () => {
    const k = 'CVE-2030-0031';
    await vuln(k, { sources: '["nvd","red-hat"]' });
    await adv('red-hat', 'RHSA-2030:1', k);
    await adv('github-advisory-db', 'GHSA-dddd-dddd-dddd', k);
    await E.SETTINGS.put('source:red-hat', '{"display":"hidden"}');
    await E.SETTINGS.put('source:github-advisory-db', '{"display":"link"}');
    let { entry } = await json(await get(`/v1/entries/${k}`, { user: true }));
    expect(entry.advisories.map((a: any) => a.source)).toEqual(['github-advisory-db']);
    expect(entry.advisories[0].display).toBe('link');
    expect(entry.aliases).toEqual(['GHSA-dddd-dddd-dddd']);
    expect(entry.credits.map((c: any) => c.sourceId)).not.toContain('red-hat');
    // malformed value: ignored, red-hat visible again
    await E.SETTINGS.put('source:red-hat', 'not json');
    await E.SETTINGS.put('source:github-advisory-db', '{"display":"bogus"}');
    ({ entry } = await json(await get(`/v1/entries/${k}`, { user: true })));
    expect(entry.advisories.map((a: any) => `${a.source}:${a.display}`)).toEqual([
      'github-advisory-db:full',
      'red-hat:full',
    ]);
    await E.SETTINGS.delete('source:red-hat');
    await E.SETTINGS.delete('source:github-advisory-db');
    // hidden cvss_source
    await E.SETTINGS.put('source:nvd', '{"display":"hidden"}');
    const vis = await json(await get(`/v1/entries/${k}`, { user: true }));
    await E.SETTINGS.delete('source:nvd');
    expect(vis.entry).not.toHaveProperty('cvss');
    expect(vis.entry).not.toHaveProperty('cvssVersion');
  });
});

describe('5. credits', () => {
  it('Credit shape, single NVD notice, unknown source not credited', async () => {
    await vuln('CVE-2030-0040', { sources: '["nvd","cisa-kev","made-up-source"]', cvss_source: 'nvd' });
    const { entry } = await json(await get('/v1/entries/CVE-2030-0040'));
    expect(entry.credits.map((c: any) => c.sourceId)).toEqual(['nvd', 'cisa-kev']);
    for (const c of entry.credits) expect(Object.keys(c).sort()).toEqual(['name', 'sourceId', 'text']);
    expect(entry.credits.filter((c: any) => c.text === NVD_NOTICE)).toHaveLength(1);
    await vuln('CVE-2030-0041', { sources: '[]', cvss_source: 'nvd' });
    const only = await json(await get('/v1/entries/CVE-2030-0041'));
    expect(only.entry.credits).toHaveLength(1);
    expect(only.entry.credits[0].text).toBe(NVD_NOTICE);
  });
});

describe('6. cache', () => {
  it('visitors hit the cache, signed-in bypass it, 404 not cached', async () => {
    const k = 'CVE-2030-0050';
    await vuln(k, { title: 'Old title' });
    const first = await get(`/v1/entries/${k}`);
    expect(first.headers.get('cache-control')).toBe('public, max-age=300');
    await E.DB_VULNS.prepare("UPDATE vulns SET title = 'New title' WHERE key = ?1").bind(k).run();
    expect((await json(await get(`/v1/entries/${k}`))).entry.title).toBe('Old title');
    const signed = await get(`/v1/entries/${k}`, { user: true });
    expect(signed.headers.get('cache-control')).toBe('private, no-store');
    const sb = await json(signed);
    expect(sb.entry.title).toBe('New title');
    expect(sb.access).toBe('full');
    const after = await json(await get(`/v1/entries/${k}`));
    expect(after.access).toBe('preview');
    expect(after.entry.title).toBe('Old title');
    // a 404 is not cached: create the row afterwards
    await adv('alias', 'late-alias', k);
    const miss = await get('/v1/entries/CVE-2030-0051');
    expect(miss.status).toBe(404);
    await vuln('CVE-2030-0051');
    expect((await get('/v1/entries/CVE-2030-0051')).status).toBe(200);
  });
});

describe('7. index', () => {
  beforeAll(async () => {
    for (const [k, t] of [
      ['CVE-2031-1', 'a'],
      ['CVE-2031-2', 'b'],
      ['cmd-1', 'c'],
      ['Chrome-1', 'd'],
      ['Cz-1', 'e'],
      ['Dx-1', 'f'],
      ['7zip-1', 'g'],
      ['0day-1', 'h'],
    ])
      await vuln(k as string, { title: t, kind: 'other' });
  });
  it('serves the R2 page when present', async () => {
    await E.BUCKET.put(
      'lookup/index/q/0.json',
      JSON.stringify({ letter: 'q', items: [{ key: 'Q1', title: 'q one' }] }),
    );
    expect(await json(await get('/v1/index/Q'))).toEqual({
      letter: 'q',
      items: [{ key: 'Q1', title: 'q one' }],
    });
  });
  it('falls back to D1 in key order, both cases, digits, cursor paging', async () => {
    const c = await json(await get('/v1/index/c'));
    const keys = c.items.map((i: any) => i.key);
    expect(keys.every((k: string) => k[0]?.toLowerCase() === 'c')).toBe(true);
    expect(keys).toEqual([...keys].sort());
    expect(keys).toEqual(expect.arrayContaining(['CVE-2031-1', 'cmd-1', 'Chrome-1', 'Cz-1']));
    const zero = await json(await get('/v1/index/0'));
    expect(zero.items.map((i: any) => i.key)).toEqual(['0day-1', '7zip-1']);
    expect((await json(await get('/v1/index/D'))).letter).toBe('d');
    // cursor: first key as cursor continues after it
    const next = await json(await get(`/v1/index/c?cursor=${encodeURIComponent(keys[0])}`));
    expect(next.items.map((i: any) => i.key)).toEqual(keys.slice(1));
  });
  it('pages of 500 continue with no repeat or gap', async () => {
    const stmts = Array.from({ length: 501 }, (_, i) =>
      E.DB_VULNS.prepare(
        "INSERT INTO vulns (key, kind, title, modified) VALUES (?1,'other','t','2025-01-01')",
      ).bind(`pg-${String(i).padStart(4, '0')}`),
    );
    await E.DB_VULNS.batch(stmts);
    const p1 = await json(await get('/v1/index/p'));
    expect(p1.items).toHaveLength(500);
    expect(p1.cursor).toBe(p1.items[499].key);
    const p2 = await json(await get(`/v1/index/p?cursor=${p1.cursor}`));
    expect(p2.cursor).toBeUndefined();
    const all = [...p1.items, ...p2.items].map((i: any) => i.key);
    expect(all.filter((k: string) => k.startsWith('pg-'))).toEqual(
      stmts.map((_, i) => `pg-${String(i).padStart(4, '0')}`),
    );
  });
  it('pages through an R2 letter, 500 at most per page, with a p<n> cursor', async () => {
    const all = Array.from({ length: 1203 }, (_, i) => ({
      key: `R-${String(i).padStart(5, '0')}`,
      title: `r ${i}`,
    }));
    for (let i = 0; i * 500 < all.length; i++) {
      const page: Record<string, unknown> = { letter: 'r', items: all.slice(i * 500, i * 500 + 500) };
      if ((i + 1) * 500 < all.length) page.cursor = `p${i + 1}`;
      await E.BUCKET.put(`lookup/index/r/${i}.json`, JSON.stringify(page));
    }
    const seen: string[] = [];
    let cursor: string | undefined;
    let pages = 0;
    do {
      const res = await json(await get(`/v1/index/r${cursor ? `?cursor=${cursor}` : ''}`));
      expect(res.items.length).toBeLessThanOrEqual(500);
      seen.push(...res.items.map((i: any) => i.key));
      cursor = res.cursor;
      pages++;
    } while (cursor && pages < 10);
    expect(pages).toBe(3);
    expect(seen).toEqual(all.map((a) => a.key));
    // a page that no longer exists is a bad cursor, not an empty list
    expect((await get('/v1/index/r?cursor=p9')).status).toBe(400);
  });
  it('ignores an old-layout letter file and uses D1', async () => {
    await E.BUCKET.put(
      'lookup/index/d.json',
      JSON.stringify({ letter: 'd', items: [{ key: 'OLD', title: 'old' }] }),
    );
    const r = await json(await get('/v1/index/d'));
    const keys = r.items.map((i: any) => i.key);
    expect(keys).not.toContain('OLD');
    expect(keys).toContain('Dx-1');
  });
  it('rejects bad letters and cursors', async () => {
    for (const l of ['ab', '%25']) {
      const r = await get(`/v1/index/${l}`);
      expect(r.status).toBe(400);
      expect(await json(r)).toEqual({ error: 'bad_letter' });
    }
    expect((await get(`/v1/index/c?cursor=${'x'.repeat(129)}`)).status).toBe(400);
  });
});

describe('8. sources', () => {
  it('lists the registry with display, lastSuccess and lastRunStatus', async () => {
    const ins = (id: string, src: string, start: string, fin: string | null, status: string) =>
      E.DB_CONTROL.prepare(
        'INSERT INTO runs (id, source_id, started_at, finished_at, status) VALUES (?1,?2,?3,?4,?5)',
      ).bind(id, src, start, fin, status);
    await E.DB_CONTROL.batch([
      ins('r1', 'nvd', '2025-01-01T00:00:00Z', '2025-01-01T00:01:00Z', 'ok'),
      ins('r2', 'nvd', '2025-01-02T00:00:00Z', '2025-01-02T00:01:00Z', 'unchanged'),
      ins('r3', 'nvd', '2025-01-03T00:00:00Z', '2025-01-03T00:01:00Z', 'failed'),
      ins('r4', 'osv', '2025-01-01T00:00:00Z', null, 'running'),
    ]);
    await E.SETTINGS.put('source:cisa-kev', '{"display":"link"}');
    const res = await get('/v1/sources');
    expect(res.headers.get('cache-control')).toBe('public, max-age=60');
    const { sources } = await json(res);
    await E.SETTINGS.delete('source:cisa-kev');
    expect(sources.map((s: any) => s.id)).toEqual(SOURCES.map((s) => s.id));
    expect(sources).toHaveLength(55);
    const by = (id: string) => sources.find((s: any) => s.id === id);
    expect(by('cisa-kev').display).toBe('link');
    expect(by('vulncheck').display).toBe('hidden');
    expect(by('nvd').lastSuccess).toBe('2025-01-02T00:01:00Z');
    expect(by('nvd').lastRunStatus).toBe('failed');
    expect(by('osv')).not.toHaveProperty('lastSuccess');
    expect(by('osv').lastRunStatus).toBe('running');
    expect(by('ubuntu')).not.toHaveProperty('lastSuccess');
    expect(by('ubuntu')).not.toHaveProperty('lastRunStatus');
  });
});

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function ulidAt(ms: number, tail: string): string {
  let t = '';
  for (let i = 0; i < 10; i++) {
    t = B32[ms % 32] + t;
    ms = Math.floor(ms / 32);
  }
  return t + tail;
}

describe('9. receipts', () => {
  it('decodes a known ULID time', () => {
    expect(decodeUlidTime('01ARZ3NDEKTSV4RRFFQ69G5FAV')).toBe(1469922850259);
    expect(Number.isNaN(decodeUlidTime('!!'))).toBe(true);
  });
  it('visitor 401; signed-in lists collector keys for ok runs only', async () => {
    const k = 'CVE-2030-0060';
    await vuln(k, { sources: '["cisa-kev"]', cvss_source: null });
    expect((await get(`/v1/entries/${k}/receipts`)).status).toBe(401);
    const ms = Date.UTC(2025, 5, 7, 12);
    const okRun = ulidAt(ms, '0'.repeat(16));
    const badRun = ulidAt(ms + 1000, '1'.repeat(16));
    await E.DB_CONTROL.batch([
      E.DB_CONTROL.prepare(
        "INSERT INTO runs (id, source_id, started_at, finished_at, status) VALUES (?1,'cisa-kev','2025-06-07T12:00:00Z','2025-06-07T12:00:05Z','ok')",
      ).bind(okRun),
      E.DB_CONTROL.prepare(
        "INSERT INTO runs (id, source_id, started_at, finished_at, status) VALUES (?1,'cisa-kev','2025-06-07T12:00:01Z','2025-06-07T12:00:05Z','failed')",
      ).bind(badRun),
    ]);
    const objKey = `raw/cisa-kev/2025/06/07/${okRun}-0.ndjson.gz`;
    await E.BUCKET.put(objKey, 'x');
    await E.BUCKET.put(`raw/cisa-kev/2025/06/07/${badRun}-0.ndjson.gz`, 'y');
    const res = await get(`/v1/entries/${k}/receipts`, { user: true });
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    const body = await json(res);
    expect(body.exact).toBe(false);
    expect(body.key).toBe(k);
    expect(body.receipts).toHaveLength(1);
    expect(body.receipts[0].runId).toBe(okRun);
    expect(body.receipts[0].objects.map((o: any) => o.key)).toEqual([objKey]);
    expect(body.receipts[0].objects[0].size).toBe(1);
    expect(body.credits[0].sourceId).toBe('cisa-kev');
  });
});

describe('10. internal errors and sitemap', () => {
  it('D1 failure is 500 internal with no detail', async () => {
    const broken = {
      ...env,
      DB_VULNS: {
        prepare() {
          throw new Error('secret detail');
        },
      },
    };
    const res = await get('/v1/entries/CVE-2030-0001', { env: broken });
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: 'internal' });
  });
  it('sitemap 404 then served from R2', async () => {
    expect((await get('/v1/sitemap.xml')).status).toBe(404);
    await E.BUCKET.put('sitemap.xml', '<urlset/>');
    const res = await get('/v1/sitemap.xml');
    expect(res.headers.get('content-type')).toBe('application/xml');
    expect(await res.text()).toBe('<urlset/>');
  });
});
