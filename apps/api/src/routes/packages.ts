import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Stub: the package-check route lands in its own change. Auth and the route's place are fixed here.
route.post('/v1/packages/check', requireUser, notImplemented);

export default route;
