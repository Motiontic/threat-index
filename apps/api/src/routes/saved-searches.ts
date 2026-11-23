import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Signed in.
route.get('/v1/me/saved-searches', requireUser, notImplemented);
route.post('/v1/me/saved-searches', requireUser, notImplemented);
route.delete('/v1/me/saved-searches/:id', requireUser, notImplemented);

export default route;
