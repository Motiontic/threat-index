import { logEvent } from '@ti/core/log';
import type { Context } from 'hono';
import { currentUserId } from './auth';
import type { AppEnv, Bindings } from './env';

/**
 * Cache key for every `caches.default` entry. Production and staging share one zone and so one cache, so the
 * key names the deployment (`TI_ENV`, set in both sections of wrangler.jsonc). It is never taken from the
 * request host: service-binding calls use the same `ti-api.internal` origin in every environment.
 */
export function publicCacheKey(env: Pick<Bindings, 'TI_ENV'>, pathAndQuery: string): Request {
  const ns = encodeURIComponent(env.TI_ENV || 'unset');
  return new Request(`https://cache.internal/${ns}${pathAndQuery}`, { method: 'GET' });
}

export const isSignedIn = (c: Context<AppEnv>): boolean => Boolean(currentUserId(c));

/**
 * Cache API wrapper for public GET routes. Auth is decided first: a signed-in request never reads or
 * writes the cache. The cache key is built from `path` alone (normalised parts chosen by the route), so no
 * header, cookie or query parameter can make it vary on auth.
 */
export async function cachedPublic(
  c: Context<AppEnv>,
  ttlSeconds: number,
  path: string,
  build: () => Promise<Response>,
): Promise<Response> {
  if (isSignedIn(c)) {
    const res = await build();
    res.headers.set('cache-control', 'private, no-store');
    return res;
  }
  const cacheKey = publicCacheKey(c.env, path);
  const hit = await caches.default.match(cacheKey);
  if (hit) return hit;
  const res = await build();
  if (res.status !== 200) return res;
  res.headers.set('cache-control', `public, max-age=${ttlSeconds}`);
  try {
    c.executionCtx.waitUntil(caches.default.put(cacheKey, res.clone()));
  } catch {
    // No execution context (some test harnesses): skip the write.
  }
  return res;
}

/** Runs a handler; any D1, R2 or KV failure becomes `500 { error: 'internal' }` with only the route logged. */
export async function guarded(
  c: Context<AppEnv>,
  route: string,
  fn: () => Promise<Response>,
): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    logEvent('error', 'guarded_failed', {
      requestId: c.get('requestId'),
      route,
      name: err instanceof Error ? err.name : 'unknown',
    });
    return c.json({ error: 'internal' }, 500);
  }
}
