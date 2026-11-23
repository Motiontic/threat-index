import { Hono } from 'hono';
import type { AppEnv } from '../lib/env';

const route = new Hono<AppEnv>();
// Mounted before clerkMiddleware, so it answers 200 even when Clerk is misconfigured.
route.get('/v1/health', (c) => c.json({ ok: true }));
export default route;
