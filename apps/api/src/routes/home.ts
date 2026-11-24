import type { HomeResponse } from '@ti/core/api';
import { Hono } from 'hono';
import { cachedPublic, guarded } from '../lib/cache';
import type { AppEnv } from '../lib/env';
import { buildHome, type HomeEnv } from '../lib/home';
import { WORLD_TTL } from '../lib/world';

const route = new Hono<AppEnv>();

/** One call for the landing page: counts per type and the newest items of each kind. Cached like the world lists. */
route.get('/v1/home', (c) =>
  guarded(c, 'GET /v1/home', () =>
    cachedPublic(c, WORLD_TTL, '/v1/home', async () => {
      const body: HomeResponse = await buildHome(c.env as HomeEnv);
      return c.json(body);
    }),
  ),
);

export default route;
