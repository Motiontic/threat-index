import { Hono } from 'hono';

import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Public.
route.get('/v1/index/:letter', notImplemented);

export default route;
