import { Hono } from 'hono';
import { verifyHmac } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// E2B callbacks only. The `x-job-signature` header is the HMAC-SHA256 hex of the job id under JOB_HMAC_SECRET.
route.use('/internal/jobs/:id/*', async (c, next) => {
  if (!(await verifyHmac(c.env.JOB_HMAC_SECRET, c.req.param('id'), c.req.header('x-job-signature'))))
    return c.json({ error: 'invalid_signature' }, 401);
  await next();
});
route.post('/internal/jobs/:id/upload-urls', notImplemented);
route.post('/internal/jobs/:id/complete', notImplemented);

export default route;
