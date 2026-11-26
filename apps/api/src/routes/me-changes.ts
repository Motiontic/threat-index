import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Stub: change notices land in their own change.
route.get('/v1/me/changes', requireUser, notImplemented);

export default route;
