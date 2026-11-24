import { Hono } from 'hono';
import { publicCacheKey } from '../lib/cache';
import type { AppEnv } from '../lib/env';
import { searchCredits } from '../lib/search-credits';
import { search } from '../lib/search-engine';
import { canonicalQuery, encodeCursor, MAX_OFFSET, parseSearchParams } from '../lib/search-params';

const route = new Hono<AppEnv>();

function defaultCache(): Cache | undefined {
  return (globalThis as { caches?: { default?: Cache } }).caches?.default;
}

// Public. The response never varies on auth, so the cache key is the URL alone.
route.get('/v1/search', async (c) => {
  const url = new URL(c.req.url);
  const parsed = parseSearchParams(url.searchParams);
  if (!parsed.ok) return c.json({ error: 'invalid_query' }, 400);
  const { params } = parsed;

  const cache = defaultCache();
  const cacheKey = publicCacheKey(c.env, `${url.pathname}?${canonicalQuery(url)}`);
  if (cache) {
    const hit = await cache.match(cacheKey);
    if (hit) {
      const res = new Response(hit.body, hit);
      res.headers.set('x-ti-cache', 'hit');
      return res;
    }
  }

  let result: Awaited<ReturnType<typeof search>>;
  try {
    result = await search(c.env, params);
  } catch (err) {
    console.error(
      JSON.stringify({
        level: 'error',
        msg: 'search_unavailable',
        q: params.q.slice(0, 200),
        err: (err instanceof Error ? err.message : String(err)).slice(0, 200),
      }),
    );
    return c.json({ error: 'search_unavailable' }, 503);
  }

  const next = params.offset + params.limit;
  const body = {
    query: params.q,
    hits: result.hits,
    total: result.total,
    ...(next < result.total && next <= MAX_OFFSET ? { cursor: encodeCursor(next, params.fingerprint) } : {}),
    credits: searchCredits(result.sources),
  };
  const res = c.json(body);
  res.headers.set('cache-control', 'public, max-age=60');
  res.headers.set('x-ti-cache', 'miss');
  if (cache) {
    try {
      c.executionCtx.waitUntil(cache.put(cacheKey, res.clone()));
    } catch {
      // No execution context (a bare unit test): skip caching.
    }
  }
  return res;
});

export default route;
