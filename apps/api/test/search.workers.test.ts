import { env } from 'cloudflare:workers';
import type { SearchHit, SearchResponse } from '@ti/core/api';
import { NVD_NOTICE } from '@ti/core/licence';
import { type SearchShard, searchShardKey, searchTerms, shardPrefix } from '@ti/core/search';
import { beforeEach, describe, expect, it } from 'vitest';
import app from '../src/index';

const BUILT = '2026-11-20T00:00:00.000Z';
interface Seed {
  key: string;
  title: string;
  summary?: string;
  published?: string | null;
  modified?: string;
  cvss?: number | null;
  kev?: string | null;
  hot?: number;
  sources?: string[];
  inShard?: boolean;
}
const SEEDS: Seed[] = [
  {
    key: 'CVE-2024-1111',
    title: 'Apache Struts remote code execution',
    cvss: 9.8,
    kev: '2024-05-01',
    published: '2024-04-01',
    sources: ['nvd', 'cisa-kev'],
  },
  {
    key: 'CVE-2023-2222',
    title: 'Struts file upload bug',
    cvss: 5.5,
    published: '2023-02-01',
    sources: ['github-advisory-db'],
  },
  {
    key: 'MAL-2024-0001',
    title: 'Malicious package stealer',
    published: '2024-06-01',
    sources: ['openssf-malicious-packages'],
  },
  { key: 'CVE-2022-4444', title: 'Cold struts row', hot: 0, published: '2022-01-01', cvss: 8 },
  // Modified after BUILT and not in any shard: only the live delta can find these.
  {
    key: 'CVE-2025-5555',
    title: 'Fresh Struts delta flaw',
    modified: '2026-11-23T12:00:00Z',
    published: '2025-05-05',
    cvss: 7.5,
    inShard: false,
    sources: ['nvd'],
  },
  {
    key: 'CVE-2021-6666',
    title: 'Login handler bypass',
    modified: '2026-11-23T12:00:00Z',
    published: '2021-01-01',
    cvss: 2.1,
    inShard: false,
  },
];

async function seedDb(rows: Seed[]) {
  await env.DB_VULNS.prepare('DELETE FROM vulns').run();
  await env.DB_ADVISORIES.prepare('DELETE FROM advisories').run();
  for (const r of rows)
    await env.DB_VULNS.prepare(
      `INSERT INTO vulns (key, kind, title, summary, published, modified, cvss, kev_added, hot, sources)
       VALUES (?, 'cve', ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        r.key,
        r.title,
        r.summary ?? '',
        r.published ?? null,
        r.modified ?? '2026-11-01T00:00:00Z',
        r.cvss ?? null,
        r.kev ?? null,
        r.hot ?? 1,
        JSON.stringify(r.sources ?? []),
      )
      .run();
}

async function clearBucket() {
  const listed = await env.BUCKET.list({ prefix: 'lookup/search/' });
  for (const o of listed.objects) await env.BUCKET.delete(o.key);
}

/** One shard per prefix, built the way the job builds them (titles only here). */
async function putShards(rows: Seed[], extra: Record<string, string[]> = {}) {
  const shards = new Map<string, SearchShard>();
  for (const r of rows.filter((s) => s.inShard !== false)) {
    const hit: SearchHit = {
      key: r.key,
      title: r.title,
      summary: r.summary ?? '',
      exploited: Boolean(r.kev),
      ...(r.cvss != null ? { cvss: r.cvss } : {}),
      ...(r.published ? { published: r.published } : {}),
    };
    for (const term of searchTerms(r.title)) {
      const p = shardPrefix(term);
      const s = shards.get(p) ?? { builtAt: BUILT, terms: {}, docs: {} };
      shards.set(p, s);
      s.terms[term] = [...(s.terms[term] ?? []), r.key].sort();
      s.docs[r.key] = hit;
    }
  }
  for (const [term, list] of Object.entries(extra)) {
    const p = shardPrefix(term);
    const s = shards.get(p) ?? { builtAt: BUILT, terms: {}, docs: {} };
    shards.set(p, s);
    s.terms[term] = list;
  }
  for (const [p, s] of shards) await env.BUCKET.put(searchShardKey(p), JSON.stringify(s));
}

let n = 0;
async function get(path: string, nonce = true) {
  const pending: Promise<unknown>[] = [];
  const url = nonce ? `${path}${path.includes('?') ? '&' : '?'}nonce=${++n}` : path;
  const res = await app.fetch(
    new Request(`https://api.test${url}`),
    env as never,
    {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughException() {},
    } as unknown as ExecutionContext,
  );
  await Promise.all(pending);
  return res;
}
const body = async (path: string) => (await (await get(path)).json()) as SearchResponse;
const keys = (r: SearchResponse) => r.hits.map((h) => h.key);

describe('GET /v1/search (Workers runtime, local D1 and R2)', () => {
  beforeEach(async () => {
    await seedDb(SEEDS);
    await clearBucket();
    await putShards(SEEDS);
    await env.DB_ADVISORIES.prepare(
      "INSERT INTO advisories (source, source_id, vuln_key, status, modified) VALUES ('github-advisory-db', 'GHSA-2222-cfgh-4444', 'CVE-2023-2222', 'active', '2026-11-01T00:00:00Z')",
    ).run();
  });

  it('finds an exact CVE in any case, without the index', async () => {
    await clearBucket();
    for (const q of ['CVE-2024-1111', 'cve-2024-1111']) {
      const r = await body(`/v1/search?q=${q}`);
      expect(keys(r)).toEqual(['CVE-2024-1111']);
      expect(r.total).toBe(1);
      expect(r.query).toBe(q);
    }
  });

  it('resolves a GHSA alias through advisories', async () => {
    const r = await body('/v1/search?q=ghsa-2222-CFGH-4444');
    expect(keys(r)).toEqual(['CVE-2023-2222']);
  });

  it('intersects two terms', async () => {
    expect(keys(await body('/v1/search?q=struts+upload'))).toEqual(['CVE-2023-2222']);
    expect(keys(await body('/v1/search?q=struts+stealer'))).toEqual([]);
  });

  it('ignores a term whose posting list is []', async () => {
    await putShards(SEEDS, { the: [] });
    const r = await body('/v1/search?q=the+upload');
    expect(keys(r)).toEqual(['CVE-2023-2222']);
  });

  it('finds a row modified after builtAt without it being in a shard', async () => {
    const r = await body('/v1/search?q=delta');
    expect(keys(r)).toEqual(['CVE-2025-5555']);
    expect(keys(await body('/v1/search?q=struts'))).toContain('CVE-2025-5555');
  });

  it('confirms whole terms in the delta: log does not match login', async () => {
    expect(keys(await body('/v1/search?q=log'))).toEqual([]);
    expect(keys(await body('/v1/search?q=login'))).toEqual(['CVE-2021-6666']);
  });

  it('never returns a non-hot row, even from a shard', async () => {
    const r = await body('/v1/search?q=struts');
    expect(keys(r)).not.toContain('CVE-2022-4444');
    await clearBucket();
    expect(keys(await body('/v1/search?q=cold'))).toEqual([]);
  });

  it('still finds a seeded row with no shards at all', async () => {
    await clearBucket();
    const r = await body('/v1/search?q=upload');
    expect(keys(r)).toEqual(['CVE-2023-2222']);
  });

  it('treats a malformed shard as missing', async () => {
    await clearBucket();
    await env.BUCKET.put(searchShardKey('st'), '{"nope":true}');
    expect(keys(await body('/v1/search?q=upload+bug'))).toEqual(['CVE-2023-2222']);
  });

  it('browses with an empty q and sig=kev', async () => {
    const r = await body('/v1/search?sig=kev');
    expect(keys(r)).toEqual(['CVE-2024-1111']);
    expect(r.total).toBe(1);
    expect(r.hits[0]?.exploited).toBe(true);
  });

  it('filters by sev, year and type', async () => {
    expect(keys(await body('/v1/search?sev=critical'))).toEqual(['CVE-2024-1111']);
    expect(keys(await body('/v1/search?sev=high&sev=low&sort=new'))).toEqual([
      'CVE-2025-5555',
      'CVE-2021-6666',
    ]);
    expect(keys(await body('/v1/search?year=2023'))).toEqual(['CVE-2023-2222']);
    expect(keys(await body('/v1/search?type=mal'))).toEqual(['MAL-2024-0001']);
    expect(keys(await body('/v1/search?type=vuln&year=2024'))).toEqual(['CVE-2024-1111']);
    expect(keys(await body('/v1/search?q=struts&sev=medium'))).toEqual(['CVE-2023-2222']);
    expect(keys(await body('/v1/search?q=package&type=mal'))).toEqual(['MAL-2024-0001']);
    expect(keys(await body('/v1/search?q=package&type=vuln'))).toEqual([]);
  });

  it('returns 200 with no hits for types we do not hold yet', async () => {
    const res = await get('/v1/search?type=breach');
    expect(res.status).toBe(200);
    const r = (await res.json()) as SearchResponse;
    expect(r).toMatchObject({ hits: [], total: 0, credits: [] });
    expect(r.cursor).toBeUndefined();
  });

  it('sorts by newest with sort=new', async () => {
    const r = await body('/v1/search?q=struts&sort=new');
    expect(keys(r)).toEqual(['CVE-2025-5555', 'CVE-2024-1111', 'CVE-2023-2222']);
  });

  it('ranks by term hits in the title, then exploited, then cvss', async () => {
    const r = await body('/v1/search?q=struts');
    expect(keys(r)).toEqual(['CVE-2024-1111', 'CVE-2025-5555', 'CVE-2023-2222']);
  });

  it('pages with a cursor to the end, and rejects a foreign cursor', async () => {
    const seen: string[] = [];
    let cursor: string | undefined;
    let pages = 0;
    do {
      const r = await body(`/v1/search?sort=new&limit=2${cursor ? `&cursor=${cursor}` : ''}`);
      seen.push(...keys(r));
      cursor = r.cursor;
      pages++;
    } while (cursor && pages < 10);
    expect(pages).toBe(3);
    expect(seen).toEqual([
      'CVE-2025-5555',
      'MAL-2024-0001',
      'CVE-2024-1111',
      'CVE-2023-2222',
      'CVE-2021-6666',
    ]);

    const first = await body('/v1/search?q=struts&limit=1');
    expect(first.cursor).toBeTruthy();
    const foreign = await get(`/v1/search?q=upload&limit=1&cursor=${first.cursor}`);
    expect(foreign.status).toBe(400);
    expect(await foreign.json()).toEqual({ error: 'invalid_query' });
    expect((await get('/v1/search?cursor=%25%25')).status).toBe(400);
  });

  it('rejects bad parameters with 400 and does not cache them', async () => {
    for (const q of [
      `q=${'a'.repeat(201)}`,
      'limit=0',
      'limit=51',
      'sev=extreme',
      'year=1998',
      'year=20x4',
      'sort=best',
      'type=nope',
      'sig=epss',
    ]) {
      const res = await get(`/v1/search?${q}`);
      expect(res.status).toBe(400);
      expect(res.headers.get('cache-control')).toBe('no-store');
    }
  });

  it('names the seeded sources and the NVD notice in credits', async () => {
    const r = await body('/v1/search?q=CVE-2024-1111');
    expect(r.credits.map((c) => c.sourceId)).toEqual(expect.arrayContaining(['nvd', 'cisa-kev']));
    expect(r.credits.some((c) => c.text === NVD_NOTICE)).toBe(true);
    expect(r.credits.every((c) => c.name && c.text)).toBe(true);
    expect((await body('/v1/search?q=nonexistentword')).credits).toEqual([]);
  });

  it('caches a 200 for 60 seconds and serves the repeat from the cache', async () => {
    const path = '/v1/search?q=upload&sort=rel';
    const first = await get(path, false);
    expect(first.headers.get('cache-control')).toBe('public, max-age=60');
    expect(first.headers.get('x-ti-cache')).toBe('miss');
    const second = await get(`${path}`, false);
    expect(second.headers.get('x-ti-cache')).toBe('hit');
    expect(await second.json()).toEqual(await first.json());
    // Parameter order does not change the key.
    expect((await get('/v1/search?sort=rel&q=upload', false)).headers.get('x-ti-cache')).toBe('hit');
  });

  it('answers 503 search_unavailable on a D1 failure, with no stack trace', async () => {
    const broken = {
      ...env,
      DB_VULNS: {
        prepare: () => {
          throw new Error('boom');
        },
      },
    };
    const res = await app.fetch(
      new Request('https://api.test/v1/search?q=failcase'),
      broken as never,
      {
        waitUntil() {},
        passThroughException() {},
      } as unknown as ExecutionContext,
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'search_unavailable' });
  });
});
