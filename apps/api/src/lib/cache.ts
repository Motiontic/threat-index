import { getAuth } from '@hono/clerk-auth';
import type { Context } from 'hono';
import type { AppEnv } from './env';

export const isSignedIn = (c: Context<AppEnv>): boolean => Boolean(getAuth(c)?.userId);

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
  const cacheKey = new Request(`https://cache.internal${path}`);
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
  } catch {
    console.error(`public-api: ${route} failed`);
    return c.json({ error: 'internal' }, 500);
  }
}
