import { CLIENT_IP_HEADER, CLIENT_SIG_HEADER, CLIENT_TS_HEADER, verifiedClientIp } from '@ti/core/edge';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiRateLimited, createAccountClient, createSiteData, parseRetryAfter } from '../app/data/api.server';
import { handleAccountAction } from '../app/lib/account-action.server';
import { BASE_HEADERS } from '../app/lib/security.server';
import { fakeApi } from './fake-api';

const handle = vi.hoisted(() => vi.fn());
const getAccount = vi.hoisted(() => vi.fn());
const cf = vi.hoisted(() => ({
  env: { TI_ENV: 'production', DATA_SOURCE: 'fixtures', API: {} } as Record<string, any>,
}));
vi.mock('cloudflare:workers', () => cf);
vi.mock('virtual:react-router/server-build', () => ({}));
vi.mock('react-router', async (orig) => ({
  ...(await orig<typeof import('react-router')>()),
  createRequestHandler: () => handle,
}));
vi.mock('../app/data/data.server', () => ({
  currentMode: () => 'fixtures',
  bridge: <T>(run: () => Promise<T>) => run(),
  getAccount,
}));

import worker from '../workers/app';

const call = (req: Request) => (worker.fetch as (r: Request) => Promise<Response>)(req);
const CTX = { requestId: 'req-launch-0001', ip: '203.0.113.9' };
const SECRET = 'edge-secret';

describe('client headers to the API', () => {
  const sources = { '/v1/sources': { body: { sources: [] } } };

  it('sends only the allow-list: accept, request id and the signed IP', async () => {
    const f = fakeApi(sources);
    await createSiteData(f.api, 'api', CTX, SECRET).sources();
    const r = f.requests[0] as Request;
    expect([...r.headers.keys()].sort()).toEqual(
      ['accept', 'x-request-id', CLIENT_IP_HEADER, CLIENT_SIG_HEADER, CLIENT_TS_HEADER].sort(),
    );
    expect(r.headers.get('cookie')).toBeNull();
    expect(r.headers.get('authorization')).toBeNull();
  });

  it('the signature verifies on the API side with the same secret, and only with it', async () => {
    const f = fakeApi(sources);
    await createSiteData(f.api, 'api', CTX, SECRET).sources();
    const h = (f.requests[0] as Request).headers;
    expect(await verifiedClientIp(SECRET, h)).toBe('203.0.113.9');
    expect(await verifiedClientIp('other', h)).toBeNull();
    expect(h.get('x-request-id')).toBe(CTX.requestId);
  });

  it('sends no IP headers without the secret or without an IP', async () => {
    const f = fakeApi(sources);
    await createSiteData(f.api, 'api', CTX).sources();
    await createSiteData(f.api, 'api', { ...CTX, ip: null }, SECRET).sources();
    for (const r of f.requests) {
      expect([...r.headers.keys()].sort()).toEqual(['accept', 'x-request-id']);
    }
  });

  it('account calls add the same headers next to Authorization', async () => {
    const f = fakeApi({ '/v1/me': { body: { id: 'x' } } });
    await createAccountClient(f.api, 'tok.en', CTX, SECRET)
      .me()
      .catch(() => {});
    const r = f.requests[0] as Request;
    expect(r.headers.get('authorization')).toBe('Bearer tok.en');
    expect(r.headers.get('cookie')).toBeNull();
    expect(await verifiedClientIp(SECRET, r.headers)).toBe('203.0.113.9');
  });
});

describe('429 from the API', () => {
  it('becomes ApiRateLimited with Retry-After, 1 to 3600, default 60', async () => {
    expect(parseRetryAfter('7')).toBe(7);
    for (const bad of [null, '0', '3601', 'abc', '1.5', '-3']) expect(parseRetryAfter(bad)).toBe(60);
    const f = fakeApi({ '/v1/sources': { status: 429, body: {}, headers: { 'retry-after': '12' } } });
    const err = await createSiteData(f.api, 'api', CTX)
      .sources()
      .catch((e) => e);
    expect(err).toBeInstanceOf(ApiRateLimited);
    expect(err.retryAfter).toBe(12);
  });

  it('account calls and actions map it to 429', async () => {
    const f = fakeApi({ '/v1/me/watch/CVE-2025-1': { status: 429, body: {} } });
    const client = createAccountClient(f.api, 'tok.en', CTX);
    const form = new FormData();
    form.set('intent', 'watch');
    form.set('id', 'CVE-2025-1');
    const res = await handleAccountAction(
      new Request('https://web.test/account/do', {
        method: 'POST',
        headers: { origin: 'https://web.test' },
        body: form,
      }),
      { getClient: async () => client },
    );
    expect(res).toEqual({ ok: false, error: 'rate_limited', status: 429 });
  });
});

describe('Worker: page limit, headers and request ids', () => {
  beforeEach(() => {
    handle.mockReset();
    Object.assign(cf.env, { TI_ENV: 'production', DATA_SOURCE: 'fixtures' });
    cf.env.RL_PAGES = undefined;
  });
  const page = (path = '/', headers: Record<string, string> = { 'cf-connecting-ip': '203.0.113.9' }) =>
    call(new Request(`https://example.test${path}`, { headers }));

  it('serves the static 429 page over the limit, without calling the router', async () => {
    const keys: string[] = [];
    cf.env.RL_PAGES = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: false }) };
    const res = await page('/search?q=x');
    expect(res.status).toBe(429);
    expect(keys).toEqual(['ip:203.0.113.9']);
    expect(handle).not.toHaveBeenCalled();
    expect(res.headers.get('retry-after')).toBe('60');
    expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; frame-ancestors 'none'");
    expect(res.headers.get('x-robots-tag')).toBe('noindex');
    expect(res.headers.get('strict-transport-security')).toContain('max-age=31536000');
    const html = await res.text();
    expect(html).toContain('Too many requests. Wait a minute and try again.');
    expect(html).toContain('href="/"');
    expect(html).not.toMatch(/<script|src=|<link/i);
  });

  it('gives a .data request a plain 429', async () => {
    cf.env.RL_PAGES = { limit: async () => ({ success: false }) };
    const res = await page('/search.data');
    expect(res.status).toBe(429);
    expect(res.headers.get('content-type')).toContain('text/plain');
    expect(res.headers.get('retry-after')).toBe('60');
  });

  it('fails open without the binding, without an IP, and when limit() throws', async () => {
    handle.mockResolvedValue(new Response('ok'));
    expect((await page()).status).toBe(200);
    cf.env.RL_PAGES = { limit: async () => ({ success: false }) };
    expect((await page('/', {})).status).toBe(200);
    cf.env.RL_PAGES = {
      limit: async () => {
        throw new Error('down');
      },
    };
    expect((await page()).status).toBe(200);
  });

  it('replaces a visitor x-request-id with a fresh one on the request and the response', async () => {
    handle.mockResolvedValue(new Response('ok'));
    const res = await page('/', { 'x-request-id': 'visitor-chosen-id', 'cf-connecting-ip': '203.0.113.9' });
    const seen = (handle.mock.calls[0]?.[0] as Request).headers.get('x-request-id');
    expect(seen).not.toBe('visitor-chosen-id');
    expect(seen).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.headers.get('x-request-id')).toBe(seen);
  });

  it('adds the base headers to resource responses, redirects, .data and keeps a CSP the page set', async () => {
    handle.mockResolvedValue(new Response('<urlset/>', { headers: { 'Content-Type': 'application/xml' } }));
    const resource = await page('/sitemap.xml');
    for (const name of Object.keys(BASE_HEADERS))
      expect(resource.headers.get(name), name).toBe(BASE_HEADERS[name]);

    handle.mockResolvedValue(new Response(null, { status: 301, headers: { Location: '/e/CVE-1' } }));
    const redirect = await page('/e/cve-1');
    expect(redirect.headers.get('strict-transport-security')).toContain('includeSubDomains');
    expect(redirect.headers.get('content-security-policy')).toContain("'nonce-");

    handle.mockResolvedValue(new Response('[]', { headers: { 'Cache-Control': 'private, no-store' } }));
    const data = await page('/search.data');
    expect(data.headers.get('cache-control')).toBe('private, no-store');
    expect(data.headers.get('x-frame-options')).toBe('DENY');

    handle.mockResolvedValue(
      new Response('<html/>', { headers: { 'Content-Security-Policy': "default-src 'self'" } }),
    );
    expect((await page()).headers.get('content-security-policy')).toBe("default-src 'self'");
  });

  it('adds Retry-After to a 429 that lacks one, and logs one request line with no query', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    handle.mockResolvedValue(new Response('slow down', { status: 429 }));
    const res = await page('/search?q=secret@example.com');
    expect(res.headers.get('retry-after')).toBe('60');
    const line = String(log.mock.calls.at(-1)?.[0]);
    log.mockRestore();
    expect(JSON.parse(line)).toMatchObject({ event: 'request', method: 'GET', path: '/search', status: 429 });
    expect(line).not.toMatch(/secret|example\.com|203\.0\.113|\?/);
  });
});

describe('/ops loader', () => {
  const REPORT = {
    generatedAt: '2026-11-23T12:00:00Z',
    sources: [],
    budget: {
      day: '2026-11-23',
      d1Writes: 1,
      d1Limit: 100,
      emailsSent: 0,
      emailCap: 95,
      queueOps: 0,
      r2ClassA: 0,
    },
    queues: [],
    jobs: { byStatus: {}, recent: [] },
    deadLetters: [],
  };
  const run = async () => {
    const { loader } = await import('../app/routes/ops');
    return loader({ request: new Request('https://web.test/ops'), params: {}, context: {} } as never);
  };
  const status = async (p: Promise<unknown>) => {
    try {
      await p;
      return 200;
    } catch (e: any) {
      return e.init?.status ?? e.status ?? 500;
    }
  };
  beforeEach(() => {
    getAccount.mockReset();
    cf.env.ADMIN_USER_IDS = 'user_admin';
  });

  it('is a 404 when signed out', async () => {
    getAccount.mockResolvedValue(null);
    expect(await status(run())).toBe(404);
  });

  it('is a 404 for a non-admin, without calling the API', async () => {
    const adminOps = vi.fn();
    getAccount.mockResolvedValue({ session: { userId: 'user_other' }, client: { adminOps } });
    expect(await status(run())).toBe(404);
    expect(adminOps).not.toHaveBeenCalled();
  });

  it('is a 404 with no admin list at all', async () => {
    cf.env.ADMIN_USER_IDS = undefined;
    const adminOps = vi.fn();
    getAccount.mockResolvedValue({ session: { userId: 'user_admin' }, client: { adminOps } });
    expect(await status(run())).toBe(404);
    expect(adminOps).not.toHaveBeenCalled();
  });

  it('is a 404 when the API answers 403 (adminOps gives null)', async () => {
    getAccount.mockResolvedValue({
      session: { userId: 'user_admin' },
      client: { adminOps: async () => null },
    });
    expect(await status(run())).toBe(404);
  });

  it('gives an admin the report, never cached', async () => {
    getAccount.mockResolvedValue({
      session: { userId: 'user_admin' },
      client: { adminOps: async () => REPORT },
    });
    const out = (await run()) as any;
    expect(out.data.report).toEqual(REPORT);
    expect(out.init.headers['Cache-Control']).toBe('private, no-store');
  });

  it('the account client calls /v1/admin/ops with Bearer and turns 403 into null', async () => {
    const ok = fakeApi({ '/v1/admin/ops': { body: REPORT } });
    expect(await createAccountClient(ok.api, 'tok.en', CTX).adminOps()).toEqual(REPORT);
    expect((ok.requests[0] as Request).headers.get('authorization')).toBe('Bearer tok.en');
    expect(new URL((ok.requests[0] as Request).url).pathname).toBe('/v1/admin/ops');
    const no = fakeApi({ '/v1/admin/ops': { status: 403, body: { error: 'forbidden' } } });
    expect(await createAccountClient(no.api, 'tok.en', CTX).adminOps()).toBeNull();
  });

  it('the guard caps lists and drops unknown fields', async () => {
    const { guardOps } = await import('../app/data/ops-guard');
    const many = (n: number, f: (i: number) => object) => Array.from({ length: n }, (_, i) => f(i));
    const out = guardOps({
      ...REPORT,
      extra: 'x',
      sources: many(250, (i) => ({
        id: `s${i}`,
        cadence: 'daily',
        ingest: true,
        lastSuccess: null,
        lastRun: null,
        failed7d: 0,
        deadLettered7d: 0,
        late: false,
        secret: 'x',
      })),
      jobs: {
        byStatus: {},
        recent: many(30, (i) => ({
          id: `j${i}`,
          kind: 'k',
          status: 's',
          sourceId: null,
          createdAt: 'now',
          finishedAt: null,
          error: 'e'.repeat(500),
        })),
      },
      deadLetters: many(30, (i) => ({ runId: `r${i}`, sourceId: 's', finishedAt: null, error: 'x' })),
    }) as any;
    expect(out.sources).toHaveLength(200);
    expect(out.jobs.recent).toHaveLength(20);
    expect(out.jobs.recent[0].error).toHaveLength(200);
    expect(out.deadLetters).toHaveLength(20);
    expect(out.extra).toBeUndefined();
    expect(out.sources[0].secret).toBeUndefined();
  });
});
