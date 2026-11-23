import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Signed in. Rate limiting lands with the feature.
route.post('/v1/deep-query', requireUser, notImplemented);
route.get('/v1/deep-query/:id', requireUser, notImplemented);

export default route;
