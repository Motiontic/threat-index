import { env } from 'cloudflare:workers';
import { signClientIp } from '@ti/core/edge';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/index';
import type { RateLimiter } from '../src/lib/env';

// Signed-in callers: the stub sets the same `clerkAuth` variable the real getAuth reads, from a header.
const stubClerk = async (c: any, next: any) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth', () => ({ userId: user ?? null }));
  await next();
};
const app = createApp(stubClerk);
app.get('/v1/boom', () => {
  throw new Error('kaboom bob@example.com');
});

const EDGE = 'test-edge-hmac-secret';
const ctx = { waitUntil() {}, passThroughException() {} } as unknown as ExecutionContext;
const call = (path: string, init?: RequestInit, e: object = env) =>
  app.fetch(new Request(`https://api.test${path}`, init), e as never, ctx);
const json = async (res: Response) => (await res.json()) as any;

function limiter(allowed = true) {
  const keys: string[] = [];
  const rl: RateLimiter = {
    limit: async ({ key }) => {
      keys.push(key);
      return { success: allowed };
    },
  };
  return { rl, keys };
}
const withRl = (o: Record<string, unknown>) => ({ ...env, ...o });

const E = env as unknown as { DB_CONTROL: D1Database; DB_USERS: D1Database };

async function signedHeaders(ip: string, ts = Math.floor(Date.now() / 1000), secret = EDGE) {
  const rid = 'req-aaaaaaaa';
  return {
    'x-request-id': rid,
    'x-ti-client-ip': ip,
    'x-ti-client-ts': String(ts),
    'x-ti-client-sig': await signClientIp(secret, ip, ts, rid),
  };
}

describe('rate limits', () => {
  it('429 body, Retry-After and no-store', async () => {
    const { rl } = limiter(false);
    const res = await call(
      '/v1/sources',
      { headers: { 'cf-connecting-ip': '203.0.113.1' } },
      withRl({ RL_PUBLIC: rl }),
    );
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('60');
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body = await json(res);
    expect(body).toMatchObject({ error: 'rate_limited', retryAfter: 60 });
    expect(body.requestId).toBe(res.headers.get('x-request-id'));
  });

  it('keys anonymous calls by IP and signed-in calls by user', async () => {
    const pub = limiter();
    const user = limiter();
    const e = withRl({ RL_PUBLIC: pub.rl, RL_USER: user.rl });
    await call('/v1/sources', { headers: { 'cf-connecting-ip': '203.0.113.1' } }, e);
    await call('/v1/sources', { headers: { 'x-test-user': 'user_1', 'cf-connecting-ip': '203.0.113.1' } }, e);
    expect(pub.keys).toEqual(['ip:203.0.113.1']);
    expect(user.keys).toEqual(['u:user_1']);
  });

  it('cuts an IPv6 address to its /64', async () => {
    const pub = limiter();
    await call(
      '/v1/sources',
      { headers: { 'cf-connecting-ip': '2001:db8:1:2:3:4:5:6' } },
      withRl({ RL_PUBLIC: pub.rl }),
    );
    expect(pub.keys).toEqual(['ip:2001:db8:1:2']);
  });

  it('honours a signed client IP over CF-Connecting-IP', async () => {
    const pub = limiter();
    const headers = { ...(await signedHeaders('198.51.100.7')), 'cf-connecting-ip': '203.0.113.1' };
    await call('/v1/sources', { headers }, withRl({ RL_PUBLIC: pub.rl }));
    expect(pub.keys).toEqual(['ip:198.51.100.7']);
  });

  it('ignores a forged or expired signature and falls back to CF-Connecting-IP', async () => {
    const pub = limiter();
    const e = withRl({ RL_PUBLIC: pub.rl });
    const forged = await signedHeaders('198.51.100.7', undefined, 'wrong-secret');
    await call('/v1/sources', { headers: { ...forged, 'cf-connecting-ip': '203.0.113.1' } }, e);
    const old = await signedHeaders('198.51.100.8', Math.floor(Date.now() / 1000) - 120);
    await call('/v1/sources', { headers: { ...old, 'cf-connecting-ip': '203.0.113.2' } }, e);
    expect(pub.keys).toEqual(['ip:203.0.113.1', 'ip:203.0.113.2']);
  });

  it('does not limit when no IP is known', async () => {
    const pub = limiter(false);
    const forged = await signedHeaders('198.51.100.7', undefined, 'wrong-secret');
    const res = await call('/v1/sources', { headers: forged }, withRl({ RL_PUBLIC: pub.rl }));
    expect(res.status).not.toBe(429);
    expect(pub.keys).toEqual([]);
  });

  it('fails open on a missing binding and on a throwing limit()', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const h = { headers: { 'cf-connecting-ip': '203.0.113.1' } };
    expect((await call('/v1/sources', h, withRl({ RL_PUBLIC: undefined }))).status).toBe(200);
    const throwing: RateLimiter = {
      limit: async () => {
        throw new Error('down');
      },
    };
    expect((await call('/v1/sources', h, withRl({ RL_PUBLIC: throwing }))).status).toBe(200);
    expect(warn.mock.calls.some((c) => String(c[0]).includes('rate_limit_unavailable'))).toBe(true);
    warn.mockRestore();
  });

  it('does not limit /v1/health', async () => {
    const { rl, keys } = limiter(false);
    const res = await call(
      '/v1/health',
      { headers: { 'cf-connecting-ip': '203.0.113.1' } },
      withRl({ RL_PUBLIC: rl }),
    );
    expect(res.status).toBe(200);
    expect(keys).toEqual([]);
  });

  it('limits /unsubscribe', async () => {
    const { rl } = limiter(false);
    const res = await call(
      '/unsubscribe?t=x',
      { headers: { 'cf-connecting-ip': '203.0.113.1' } },
      withRl({ RL_PUBLIC: rl }),
    );
    expect(res.status).toBe(429);
  });

  it('the deep-query per-minute limit answers before the hourly check', async () => {
    const deep = limiter(false);
    const res = await call(
      '/v1/deep-query',
      { method: 'POST', headers: { 'x-test-user': 'user_1' }, body: '{}' },
      withRl({ RL_DEEP: deep.rl }),
    );
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('60');
    expect(deep.keys).toEqual(['u:user_1']);
  });

  it('the real Miniflare RL_PUBLIC binding exists and returns success', async () => {
    const real = (env as unknown as { RL_PUBLIC: RateLimiter }).RL_PUBLIC;
    expect(real).toBeDefined();
    expect((await real.limit({ key: 'test' })).success).toBe(true);
  });
});

describe('errors and request ids', () => {
  afterEach(() => vi.restoreAllMocks());

  it('an unknown path is a 404 JSON with a request id', async () => {
    const res = await call('/v1/nope');
    expect(res.status).toBe(404);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(await json(res)).toEqual({ error: 'not_found', requestId: res.headers.get('x-request-id') });
  });

  it('a throwing route is a 500 with a request id and logs the error name only', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await call('/v1/boom');
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: 'internal', requestId: res.headers.get('x-request-id') });
    expect(res.headers.get('cache-control')).toBe('no-store');
    const line = String(err.mock.calls[0]?.[0]);
    expect(JSON.parse(line)).toMatchObject({ event: 'unhandled_error', name: 'Error' });
    expect(line).not.toContain('kaboom');
  });

  it('guarded() answers 500 { error } and logs the route', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await call('/v1/breaches', undefined, withRl({ DB_WORLD: undefined }));
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: 'internal' });
    expect(err.mock.calls.some((c) => String(c[0]).includes('guarded_failed'))).toBe(true);
  });

  it('keeps a valid x-request-id and replaces an invalid one', async () => {
    const kept = await call('/v1/health', { headers: { 'x-request-id': 'abc-12345678' } });
    expect(kept.headers.get('x-request-id')).toBe('abc-12345678');
    const replaced = await call('/v1/health', { headers: { 'x-request-id': 'bad id!' } });
    expect(replaced.headers.get('x-request-id')).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('security headers', () => {
  const must = (res: Response) => {
    expect(res.headers.get('strict-transport-security')).toBe('max-age=31536000; includeSubDomains');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('permissions-policy')).toContain('camera=()');
  };
  it('are on JSON, 404, 429 and health', async () => {
    const h = { headers: { 'cf-connecting-ip': '203.0.113.1' } };
    for (const res of [
      await call('/v1/sources', h),
      await call('/v1/nope'),
      await call('/v1/sources', h, withRl({ RL_PUBLIC: limiter(false).rl })),
      await call('/v1/health'),
    ]) {
      must(res);
      expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; frame-ancestors 'none'");
    }
  });
  it('leave the /unsubscribe CSP intact', async () => {
    const res = await call('/unsubscribe?t=bad', { headers: { 'cf-connecting-ip': '203.0.113.1' } });
    must(res);
    expect(res.headers.get('content-security-policy')).toContain("style-src 'unsafe-inline'");
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
  });
});

describe('GET /v1/admin/ops', () => {
  beforeEach(async () => {
    const day = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    for (const t of ['runs', 'jobs', 'budget']) await E.DB_CONTROL.prepare(`DELETE FROM ${t}`).run();
    await E.DB_USERS.prepare('DELETE FROM email_log').run();
    await E.DB_CONTROL.batch([
      E.DB_CONTROL.prepare(
        "INSERT INTO runs (id, source_id, started_at, finished_at, status) VALUES ('r1','cisa-kev',?1,?1,'ok')",
      ).bind(now),
      E.DB_CONTROL.prepare(
        "INSERT INTO runs (id, source_id, started_at, finished_at, status, error) VALUES ('r2','epss',?1,?1,'failed','dead-lettered after 6 attempts: boom')",
      ).bind(now),
      E.DB_CONTROL.prepare(
        "INSERT INTO jobs (id, kind, source_id, status, created_at, error) VALUES ('j1','deep-query','user-id-hash','failed',?1,'x')",
      ).bind(now),
      E.DB_CONTROL.prepare(
        "INSERT INTO jobs (id, kind, source_id, status, created_at) VALUES ('j2','first-load','cisa-kev','running',?1)",
      ).bind(now),
      E.DB_CONTROL.prepare('INSERT INTO budget (day, d1_writes, emails_sent) VALUES (?1, 1234, 77)').bind(
        day,
      ),
    ]);
    await E.DB_USERS.prepare('INSERT INTO email_log (day, sent) VALUES (?1, 5)').bind(day).run();
  });

  it('is 403 for anonymous and for non-admin callers, the same answer', async () => {
    const anon = await call('/v1/admin/ops');
    const other = await call('/v1/admin/ops', { headers: { 'x-test-user': 'user_other' } });
    expect(anon.status).toBe(403);
    expect(other.status).toBe(403);
    expect(await json(anon)).toEqual({ error: 'forbidden' });
    expect(await json(other)).toEqual({ error: 'forbidden' });
  });

  it('is 403 for everyone when ADMIN_USER_IDS is empty', async () => {
    const res = await call(
      '/v1/admin/ops',
      { headers: { 'x-test-user': 'user_admin' } },
      withRl({ ADMIN_USER_IDS: '' }),
    );
    expect(res.status).toBe(403);
  });

  it('gives an admin the report, never cached', async () => {
    const res = await call('/v1/admin/ops', { headers: { 'x-test-user': 'user_admin' } });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    const r = await json(res);
    expect(r.budget).toMatchObject({ d1Writes: 1234, emailsSent: 5, d1Limit: 100000 });
    const epss = r.sources.find((s: any) => s.id === 'epss');
    expect(epss).toMatchObject({ failed7d: 1, deadLettered7d: 1 });
    expect(r.sources.find((s: any) => s.id === 'cisa-kev').lastSuccess).not.toBeNull();
    expect(r.deadLetters).toHaveLength(1);
    expect(r.deadLetters[0]).toMatchObject({ runId: 'r2', sourceId: 'epss' });
    const deep = r.jobs.recent.find((j: any) => j.id === 'j1');
    expect(deep.sourceId).toBeNull();
    expect(r.jobs.recent.find((j: any) => j.id === 'j2').sourceId).toBe('cisa-kev');
    expect(r.jobs.byStatus).toMatchObject({ failed: 1, running: 1 });
    expect(r.queues.map((q: any) => q.name)).toEqual(['ti-jobs', 'ti-jobs-dlq', 'ti-load']);
  });

  it('applies the per-user limit', async () => {
    const res = await call(
      '/v1/admin/ops',
      { headers: { 'x-test-user': 'user_admin' } },
      withRl({ RL_USER: limiter(false).rl }),
    );
    expect(res.status).toBe(429);
  });
});

describe('logs', () => {
  it('hold no email, token, IP or query string', async () => {
    const spies = [
      vi.spyOn(console, 'log').mockImplementation(() => {}),
      vi.spyOn(console, 'warn').mockImplementation(() => {}),
      vi.spyOn(console, 'error').mockImplementation(() => {}),
    ];
    const h = { 'cf-connecting-ip': '203.0.113.77', authorization: 'Bearer sekret-token-value' };
    await call('/v1/search?q=bob@example.com&secretparam=1', { headers: h });
    await call('/v1/boom?email=bob@example.com', { headers: h });
    await call('/v1/nope?t=sekret-token-value', { headers: h });
    await call('/v1/sources', { headers: h }, withRl({ RL_PUBLIC: limiter(false).rl }));
    await call('/unsubscribe?t=sekret-token-value', { headers: h });
    const lines = spies.flatMap((s) => s.mock.calls.map((c) => String(c[0])));
    for (const s of spies) s.mockRestore();
    expect(lines.length).toBeGreaterThan(4);
    for (const line of lines) {
      expect(line).not.toMatch(/example\.com|sekret|203\.0\.113|secretparam|\?/);
      expect(() => JSON.parse(line)).not.toThrow();
    }
    expect(lines.some((l) => l.includes('"event":"request"'))).toBe(true);
  });
});
