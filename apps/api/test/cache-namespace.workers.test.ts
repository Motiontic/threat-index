import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { publicCacheKey } from '../src/lib/cache';

// Production and staging share one zone and so one Cache API. Two environments with different TI_ENV values
// must never read each other's entry for the same path and query.
const { Hono } = await import('hono');
const { default: home } = await import('../src/routes/home');
const { default: search } = await import('../src/routes/search');
const app = new Hono();
app.use('/v1/*', async (c, next) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
  await next();
});
app.route('/', home as never);
app.route('/', search as never);

const PROD = { ...env, TI_ENV: 'production' };
const STAGING = { ...env, TI_ENV: 'staging' };

async function get(e: object, path: string, headers?: Record<string, string>) {
  const ctx = createExecutionContext();
  const res = await app.fetch(new Request(`https://ti-api.internal${path}`, { headers }), e as never, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

describe('publicCacheKey', () => {
  it('differs by environment and keeps path and query', () => {
    const a = publicCacheKey({ TI_ENV: 'production' }, '/v1/home').url;
    const b = publicCacheKey({ TI_ENV: 'staging' }, '/v1/home').url;
    expect(a).toBe('https://cache.internal/production/v1/home');
    expect(b).toBe('https://cache.internal/staging/v1/home');
  });
});

describe('cache namespace', () => {
  it('home: an environment hits its own entry and never the other one', async () => {
    const path = '/v1/home';
    await get(PROD, path); // writes production's entry
    const cached = await caches.default.match(publicCacheKey(PROD, path));
    expect(cached).toBeTruthy();
    expect(await caches.default.match(publicCacheKey(STAGING, path))).toBeUndefined();
    // Plant a marker in production's entry; staging must not serve it, production must.
    await caches.default.put(
      publicCacheKey(PROD, path),
      new Response(JSON.stringify({ marker: 'production' }), {
        headers: { 'cache-control': 'public, max-age=300' },
      }),
    );
    expect(await (await get(PROD, path)).json()).toEqual({ marker: 'production' });
    const stag = await get(STAGING, path);
    expect(await stag.json()).not.toEqual({ marker: 'production' });
    expect(await caches.default.match(publicCacheKey(STAGING, path))).toBeTruthy();
  });

  it('search: same query, different environments, separate entries', async () => {
    const path = '/v1/search?q=nsprobe&sort=rel';
    const key = (e: { TI_ENV: string }) => publicCacheKey(e, '/v1/search?q=nsprobe&sort=rel');
    await caches.default.put(
      key(PROD),
      new Response(JSON.stringify({ marker: 'production' }), {
        headers: { 'cache-control': 'public, max-age=60' },
      }),
    );
    const prod = await get(PROD, path);
    expect(prod.headers.get('x-ti-cache')).toBe('hit');
    expect(await prod.json()).toEqual({ marker: 'production' });
    const stag = await get(STAGING, path);
    expect(stag.headers.get('x-ti-cache')).not.toBe('hit');
    // Staging's own repeat hits staging's entry, with the sorted query string.
    const again = await get(STAGING, '/v1/search?sort=rel&q=nsprobe');
    if (stag.status === 200) expect(again.headers.get('x-ti-cache')).toBe('hit');
  });

  it('signed-in requests bypass the cache', async () => {
    const path = '/v1/home';
    await caches.default.put(
      publicCacheKey(STAGING, path),
      new Response(JSON.stringify({ marker: 'cached' }), {
        headers: { 'cache-control': 'public, max-age=300' },
      }),
    );
    const res = await get(STAGING, path, { 'x-test-user': 'user_1' });
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    expect(await res.json()).not.toEqual({ marker: 'cached' });
  });
});
