import type { BreachSummary, WorldList } from '@ti/core/world-api';
import { Hono } from 'hono';
import { cachedPublic, guarded } from '../lib/cache';
import type { AppEnv } from '../lib/env';
import {
  cacheKey,
  isListError,
  parseListQuery,
  validPrintableId,
  visibleSources,
  WORLD_TTL,
  type WorldEnv,
} from '../lib/world';
import { breachDetail, listBreaches } from '../lib/world-breach';

const route = new Hono<AppEnv>();

route.get('/v1/breaches', (c) =>
  guarded(c, 'GET /v1/breaches', async () => {
    const env = c.env as WorldEnv;
    const query = parseListQuery(new URL(c.req.url), () => null);
    if (isListError(query)) return c.json({ error: query.error }, 400);
    const path = cacheKey('/v1/breaches', [
      ['page', query.page],
      ['q', query.q],
    ]);
    return cachedPublic(c, WORLD_TTL, path, async () => {
      const v = await visibleSources(env);
      const r = await listBreaches(env, v, query.q, query.page);
      const body: WorldList<BreachSummary> = {
        items: r.items,
        page: query.page,
        next: r.next,
        credits: r.credits,
      };
      return c.json(body);
    });
  }),
);

route.get('/v1/breaches/:key', (c) =>
  guarded(c, 'GET /v1/breaches/:key', async () => {
    const env = c.env as WorldEnv;
    const key = c.req.param('key');
    if (!validPrintableId(key)) return c.json({ error: 'bad_id' }, 400);
    return cachedPublic(c, WORLD_TTL, `/v1/breaches/${encodeURIComponent(key)}`, async () => {
      const v = await visibleSources(env);
      const detail = await breachDetail(env, v, key);
      if (!detail) return c.json({ error: 'not_found' }, 404);
      return c.json(detail);
    });
  }),
);

export default route;
