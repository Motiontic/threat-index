import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Stubs: package watches land in their own change.
route.get('/v1/me/watch/packages', requireUser, notImplemented);
route.put('/v1/me/watch/packages/:ecosystem/:name', requireUser, notImplemented);
route.delete('/v1/me/watch/packages/:ecosystem/:name', requireUser, notImplemented);

export default route;
