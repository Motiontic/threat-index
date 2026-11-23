import { Hono } from 'hono';
import { verifySvix } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

// Svix-signed. Bounce/complaint handling lands with alerts; the signature check is already enforced.
route.post('/webhooks/resend', async (c) => {
  try {
    await verifySvix(c, c.env.RESEND_WEBHOOK_SECRET);
  } catch {
    return c.text('Verification failed', 400);
  }
  return notImplemented(c);
});

export default route;
