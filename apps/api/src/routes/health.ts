import { Hono } from 'hono';
import type { AppEnv } from '../lib/env';

const route = new Hono<AppEnv>();
route.get('/v1/health', (c) => c.json({ ok: true }));
export default route;
