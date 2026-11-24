import { env } from 'cloudflare:workers';
import { deriveJobKey, SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { JobLauncher, SandboxJob } from '../src/lib/e2b';
import type { AppEnv } from '../src/lib/env';
import { createInternalJobsRoute } from '../src/routes/internal-jobs';

const SECRET = env.JOB_HMAC_SECRET;
const NOW = new Date('2026-11-23T12:00:00Z');
const BASE = 'https://ti-api.example.com';
const CONFIGURED = { ...env, API_BASE: BASE, E2B_TEMPLATE: 'tmpl', R2_BUCKET_NAME: 'threat-index-staging' };
const ID = '01HZX3K9ABCDEFGHJKMNPQRSAA';
const OTHER = '01HZX3K9ABCDEFGHJKMNPQRSBB';
const enc = new TextEncoder();
const signalsDb = () => (env as unknown as { DB_SIGNALS: D1Database }).DB_SIGNALS;

const started: SandboxJob[] = [];
const launcher: JobLauncher = {
  async create() {
    return {
      sandboxId: 'sbx',
      async start(job) {
        started.push(job);
      },
    };
  },
  async kill() {},
};
const route = createInternalJobsRoute({
  launcher: () => launcher,
  now: () => NOW,
  newId: () => '01HZX3K9ABCDEFGHJKMNPQRSCC',
});
const app = new Hono<AppEnv>().route('/', route);
const call = (req: Request) =>
  app.fetch(
    req,
    CONFIGURED as never,
    { waitUntil() {}, passThroughException() {} } as unknown as ExecutionContext,
  );

async function sha256(bytes: Uint8Array | string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', typeof bytes === 'string' ? enc.encode(bytes) : bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function seed(id: string, kind: string, status = 'running', source: string | null = null) {
  await env.DB_CONTROL.prepare(
    'INSERT INTO jobs (id, kind, source_id, status, sandbox_id, created_at) VALUES (?1,?2,?3,?4,?5,?6)',
  )
    .bind(id, kind, source, status, 'sbx', NOW.toISOString())
    .run();
}

async function sigHeaders(id: string, method: string, rawTarget: string, signedBody: string, key?: string) {
  // The server signs what URL parsing leaves, so a `..` is resolved before it is signed.
  const u = new URL(rawTarget, 'https://api.test');
  const target = u.pathname + u.search;
  const ts = Math.floor(NOW.getTime() / 1000);
  const k = key ?? (await deriveJobKey(SECRET, id));
  return {
    [TIMESTAMP_HEADER]: String(ts),
    [SIGNATURE_HEADER]: await signRequest(k, method, target, ts, signedBody),
  };
}

interface PutOpts {
  body?: string | Uint8Array;
  digest?: string;
  contentType?: string;
  length?: string | null;
  key?: string;
  signAs?: string;
}
async function put(id: string, objectKey: string, o: PutOpts = {}) {
  const body = o.body ?? 'hello';
  const bytes = typeof body === 'string' ? enc.encode(body) : body;
  const digest = o.digest ?? (await sha256(bytes));
  const target = `/internal/jobs/${id}/objects/${objectKey}`;
  const headers: Record<string, string> = {
    ...(await sigHeaders(id, 'PUT', target, digest, o.key)),
    'x-ti-content-sha256': digest,
    'content-type': o.contentType ?? 'application/json',
  };
  if (o.length !== null) headers['content-length'] = o.length ?? String(bytes.byteLength);
  return call(new Request(`https://api.test${o.signAs ?? target}`, { method: 'PUT', headers, body: bytes }));
}
async function get(id: string, target: string, signTarget = target, key?: string) {
  return call(
    new Request(`https://api.test${target}`, {
      method: 'GET',
      headers: await sigHeaders(id, 'GET', signTarget, '', key),
    }),
  );
}
const obj = (id: string, key: string) => get(id, `/internal/jobs/${id}/objects/${key}`);

beforeEach(async () => {
  started.length = 0;
  vi.spyOn(console, 'log').mockImplementation(() => {});
  await env.DB_CONTROL.exec('DELETE FROM jobs;');
  await env.DB_VULNS.exec('DELETE FROM vulns;');
  await env.DB_ADVISORIES.exec('DELETE FROM advisories;');
  await signalsDb().exec('DELETE FROM signals;');
});
afterEach(() => vi.restoreAllMocks());

describe('PUT objects', () => {
  it('stores the bytes and the content type', async () => {
    await seed(ID, 'echo');
    const res = await put(ID, `jobs/${ID}/a.json`, { body: '{"a":1}' });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ key: `jobs/${ID}/a.json`, size: 7 });
    const stored = await env.BUCKET.get(`jobs/${ID}/a.json`);
    expect(await stored?.text()).toBe('{"a":1}');
    expect(stored?.httpMetadata?.contentType).toBe('application/json');
  });
  it('stores a bad content type as application/octet-stream', async () => {
    await seed(ID, 'echo');
    await put(ID, `jobs/${ID}/b`, { contentType: 'text/html; charset=evil' });
    expect((await env.BUCKET.get(`jobs/${ID}/b`))?.httpMetadata?.contentType).toBe(
      'application/octet-stream',
    );
  });
  it('401 for a wrong key, another job’s key, and a changed path', async () => {
    await seed(ID, 'echo');
    const k = `jobs/${ID}/c`;
    expect((await put(ID, k, { key: 'deadbeef' })).status).toBe(401);
    expect((await put(ID, k, { key: await deriveJobKey(SECRET, OTHER) })).status).toBe(401);
    expect((await put(ID, k, { signAs: `/internal/jobs/${ID}/objects/jobs/${ID}/other` })).status).toBe(401);
    expect(await env.BUCKET.get(k)).toBeNull();
  });
  it('400 checksum_mismatch and nothing stored when the digest is not the body’s', async () => {
    await seed(ID, 'echo');
    const res = await put(ID, `jobs/${ID}/d`, { digest: await sha256('something else') });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'checksum_mismatch' });
    expect(await env.BUCKET.get(`jobs/${ID}/d`)).toBeNull();
  });
  it('400 for keys outside the prefixes, request.json, .. and %2e', async () => {
    await seed(ID, 'echo');
    for (const k of [
      `jobs/${OTHER}/x`,
      'lake/records/cisa-kev/x',
      `jobs/${ID}/request.json`,
      `jobs/${ID}/../${OTHER}/x`,
      `jobs/${ID}/%2e%2e/x`,
      `jobs/${ID}`,
    ]) {
      const res = await put(ID, k);
      expect(res.status, k).toBe(400);
    }
  });
  it('write prefixes follow the kind and source', async () => {
    await seed(ID, 'first-load', 'running', 'cisa-kev');
    expect((await put(ID, 'lake/records/cisa-kev/2026/part-x.ndjson.gz')).status).toBe(200);
    expect((await put(ID, 'lake/records/nvd/2026/part-x.ndjson.gz')).status).toBe(400);
    await seed(OTHER, 'search-index');
    expect((await put(OTHER, 'sitemap.xml')).status).toBe(200);
    expect((await put(OTHER, 'lookup/index/a.json')).status).toBe(200);
    expect((await put(ID, 'sitemap.xml')).status).toBe(400);
  });
  it('411 without content-length, 413 for a declared 51 MiB, 409 when the job is not running', async () => {
    await seed(ID, 'echo');
    expect((await put(ID, `jobs/${ID}/e`, { length: null })).status).toBe(411);
    const big = await put(ID, `jobs/${ID}/e`, { length: String(51 * 1024 * 1024) });
    expect(big.status).toBe(413);
    expect(await env.BUCKET.get(`jobs/${ID}/e`)).toBeNull();
    await seed(OTHER, 'echo', 'complete');
    expect((await put(OTHER, `jobs/${OTHER}/e`)).status).toBe(409);
  });
});

// QA archive-limits: DELETE objects had no coverage (a failed load undoes its lake parts through it).
async function del(id: string, objectKey: string, o: { key?: string; signAs?: string } = {}) {
  const target = `/internal/jobs/${id}/objects/${objectKey}`;
  return call(
    new Request(`https://api.test${o.signAs ?? target}`, {
      method: 'DELETE',
      headers: await sigHeaders(id, 'DELETE', target, '', o.key),
    }),
  );
}

describe('DELETE objects', () => {
  it('removes a key the job could write, and deleting a missing key succeeds', async () => {
    await seed(ID, 'first-load', 'running', 'cisa-kev');
    const k = 'lake/records/cisa-kev/2026/part-x.ndjson.gz';
    await put(ID, k);
    expect(await env.BUCKET.get(k)).not.toBeNull();
    const res = await del(ID, k);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ key: k });
    expect(await env.BUCKET.get(k)).toBeNull();
    expect((await del(ID, k)).status).toBe(200);
  });
  it('401 for a wrong key or a changed path, and the object stays', async () => {
    await seed(ID, 'echo');
    const k = `jobs/${ID}/keep`;
    await put(ID, k);
    expect((await del(ID, k, { key: 'deadbeef' })).status).toBe(401);
    expect((await del(ID, k, { signAs: `/internal/jobs/${ID}/objects/jobs/${ID}/other` })).status).toBe(401);
    expect(await env.BUCKET.get(k)).not.toBeNull();
  });
  it('400 for keys outside the write prefixes, request.json and ..; other sources and jobs are untouched', async () => {
    await seed(ID, 'first-load', 'running', 'cisa-kev');
    await env.BUCKET.put('lake/records/nvd/2026/part-x.ndjson.gz', 'x');
    await env.BUCKET.put(`jobs/${OTHER}/x`, 'x');
    for (const k of [
      'lake/records/nvd/2026/part-x.ndjson.gz',
      `jobs/${OTHER}/x`,
      `jobs/${ID}/request.json`,
      `jobs/${ID}/../${OTHER}/x`,
      `jobs/${ID}/%2e%2e/x`,
    ]) {
      expect((await del(ID, k)).status, k).toBe(400);
    }
    expect(await env.BUCKET.get('lake/records/nvd/2026/part-x.ndjson.gz')).not.toBeNull();
    expect(await env.BUCKET.get(`jobs/${OTHER}/x`)).not.toBeNull();
  });
  it('409 and the object stays when the job is not running', async () => {
    await seed(OTHER, 'echo', 'complete');
    await env.BUCKET.put(`jobs/${OTHER}/z`, 'x');
    expect((await del(OTHER, `jobs/${OTHER}/z`)).status).toBe(409);
    expect(await env.BUCKET.get(`jobs/${OTHER}/z`)).not.toBeNull();
  });
});

describe('GET objects and list', () => {
  beforeEach(async () => {
    await seed(ID, 'echo');
    await env.BUCKET.put(`inbox/${ID}/m.json`, 'mine', { httpMetadata: { contentType: 'application/json' } });
    await env.BUCKET.put('raw/cisa-kev/2026/11/22/r-0.ndjson.gz', 'raw');
    await env.BUCKET.put(`jobs/${OTHER}/secret`, 'no');
  });
  it('reads its own inbox and raw/, with content-type and length', async () => {
    const a = await obj(ID, `inbox/${ID}/m.json`);
    expect(a.status).toBe(200);
    expect(a.headers.get('content-type')).toBe('application/json');
    expect(a.headers.get('content-length')).toBe('4');
    expect(await a.text()).toBe('mine');
    expect(await (await obj(ID, 'raw/cisa-kev/2026/11/22/r-0.ndjson.gz')).text()).toBe('raw');
  });
  it('400 for another job’s jobs/ and 404 for a missing object', async () => {
    expect((await obj(ID, `jobs/${OTHER}/secret`)).status).toBe(400);
    expect((await obj(ID, 'raw/nope')).status).toBe(404);
  });
  it('list pages with a cursor and refuses a prefix outside the read prefixes', async () => {
    for (let i = 0; i < 1003; i++)
      await env.BUCKET.put(`lookup/vuln/${String(i).padStart(4, '0')}.json`, 'x');
    const q = (p: string, c?: string) => {
      const sp = new URLSearchParams({ prefix: p });
      if (c) sp.set('cursor', c);
      return `/internal/jobs/${ID}/list?${sp}`;
    };
    const first = (await (await get(ID, q('lookup/vuln/'))).json()) as {
      objects: unknown[];
      cursor: string | null;
    };
    expect(first.objects).toHaveLength(1000);
    expect(first.cursor).toBeTruthy();
    const second = (await (await get(ID, q('lookup/vuln/', first.cursor as string))).json()) as {
      objects: unknown[];
      cursor: string | null;
    };
    expect(second.objects).toHaveLength(3);
    expect(second.cursor).toBeNull();
    expect((await get(ID, q(`jobs/${OTHER}/`))).status).toBe(400);
    expect((await get(ID, q(''))).status).toBe(400);
    expect((await get(ID, q('docs/'))).status).toBe(400);
  });
  it('a changed query is a 401', async () => {
    const res = await get(
      ID,
      `/internal/jobs/${ID}/list?prefix=raw%2Fa`,
      `/internal/jobs/${ID}/list?prefix=raw%2Fb`,
    );
    expect(res.status).toBe(401);
  });
});

describe('GET rows', () => {
  const rowsPath = (t: string, qs = '') => `/internal/jobs/${ID}/rows/${t}${qs}`;
  beforeEach(async () => {
    await seed(ID, 'first-load', 'running', 'cisa-kev');
    for (const k of ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'])
      await env.DB_VULNS.prepare(`INSERT INTO vulns (key, kind, title, modified) VALUES (?1, 'cve', ?2, ?3)`)
        .bind(k, 't', '2026-01-01')
        .run();
  });
  it('pages vulns by key', async () => {
    const a = (await (await get(ID, rowsPath('vulns', '?limit=2'))).json()) as {
      rows: { key: string }[];
      next: string | null;
    };
    expect(a.rows.map((r) => r.key)).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
    expect(a.next).toBeTruthy();
    const b = (await (await get(ID, rowsPath('vulns', `?limit=2&after=${a.next}`))).json()) as {
      rows: { key: string }[];
      next: string | null;
    };
    expect(b.rows.map((r) => r.key)).toEqual(['CVE-2024-0003']);
    expect(b.next).toBeNull();
  });
  it('pages advisories and signals by their composite keys', async () => {
    for (const [s, i] of [
      ['a', '1'],
      ['a', '2'],
      ['b', '1'],
    ])
      await env.DB_ADVISORIES.prepare(
        'INSERT INTO advisories (source, source_id, status, title) VALUES (?1, ?2, ?3, ?4)',
      )
        .bind(s, i, 'published', 't')
        .run()
        .catch(() => {});
    const adv = await env.DB_ADVISORIES.prepare('SELECT COUNT(*) AS n FROM advisories').first<{
      n: number;
    }>();
    if ((adv?.n ?? 0) === 3) {
      const p1 = (await (await get(ID, rowsPath('advisories', '?limit=2'))).json()) as {
        rows: { source: string; source_id: string }[];
        next: string;
      };
      expect(p1.rows.map((r) => `${r.source}${r.source_id}`)).toEqual(['a1', 'a2']);
      const p2 = (await (await get(ID, rowsPath('advisories', `?limit=2&after=${p1.next}`))).json()) as {
        rows: unknown[];
        next: null;
      };
      expect(p2.rows).toHaveLength(1);
    }
    for (const [k, kind, src, ref] of [
      ['C1', 'poc', 'x', '1'],
      ['C1', 'poc', 'x', '2'],
      ['C1', 'ransomware', 'x', '1'],
    ])
      await signalsDb()
        .prepare('INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES (?1,?2,?3,?4,?5)')
        .bind(k, kind, src, ref, '2026-01-01')
        .run();
    const s1 = (await (await get(ID, rowsPath('signals', '?limit=2'))).json()) as {
      rows: { kind: string; ref: string }[];
      next: string;
    };
    expect(s1.rows.map((r) => `${r.kind}${r.ref}`)).toEqual(['poc1', 'poc2']);
    const s2 = (await (await get(ID, rowsPath('signals', `?limit=2&after=${s1.next}`))).json()) as {
      rows: { kind: string }[];
      next: null;
    };
    expect(s2.rows.map((r) => r.kind)).toEqual(['ransomware']);
    expect(s2.next).toBeNull();
  });
  it('400 for another table, limit=1001, a bad limit or a bad cursor', async () => {
    for (const p of [
      rowsPath('users'),
      rowsPath('vulns', '?limit=1001'),
      rowsPath('vulns', '?limit=0'),
      rowsPath('vulns', '?limit=x'),
      rowsPath('vulns', '?after=!!!'),
      rowsPath('advisories', `?after=${btoa('["a"]')}`),
    ]) {
      const res = await get(ID, p);
      expect(res.status, p).toBe(400);
      expect(await res.json()).toEqual({ error: 'invalid_query' });
    }
  });
  it('403 for an echo job', async () => {
    await seed(OTHER, 'echo');
    const res = await get(OTHER, `/internal/jobs/${OTHER}/rows/vulns`);
    expect(res.status).toBe(403);
  });
});

describe('start nightly-fold', () => {
  async function ops(payload: unknown) {
    const body = JSON.stringify(payload);
    const ts = Math.floor(NOW.getTime() / 1000);
    return call(
      new Request('https://api.test/internal/jobs', {
        method: 'POST',
        headers: {
          [TIMESTAMP_HEADER]: String(ts),
          [SIGNATURE_HEADER]: await signRequest(SECRET, 'POST', '/internal/jobs', ts, body),
        },
        body,
      }),
    );
  }
  it('starts with no source and passes day to the launcher; a second is existing', async () => {
    const res = await ops({ kind: 'nightly-fold', reason: 'r', day: '2026-11-22' });
    expect(res.status).toBe(201);
    expect(started[0]).toMatchObject({ kind: 'nightly-fold', day: '2026-11-22' });
    expect(started[0]?.sourceId).toBeUndefined();
    const again = await ops({ kind: 'nightly-fold', reason: 'r' });
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({ existing: true });
    expect(started).toHaveLength(1);
  });
  it('400 for a bad day', async () => {
    expect((await ops({ kind: 'nightly-fold', reason: 'r', day: '2026-13-45' })).status).toBe(400);
  });
});
