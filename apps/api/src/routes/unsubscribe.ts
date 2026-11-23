import { Hono } from 'hono';
import { verifyHmac } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';

const route = new Hono<AppEnv>();

/** Token format: `<payload>.<hmac-sha256 hex of payload>`, signed with UNSUBSCRIBE_SECRET. */
async function tokenOk(secret: string | undefined, token: string | undefined): Promise<boolean> {
  const dot = token?.lastIndexOf('.') ?? -1;
  if (!token || dot < 1) return false;
  return verifyHmac(secret, token.slice(0, dot), token.slice(dot + 1));
}

// Signed token. GET shows a confirmation, POST is the RFC 8058 one-click.
for (const method of ['get', 'post'] as const) {
  route[method]('/unsubscribe', async (c) => {
    if (!(await tokenOk(c.env.UNSUBSCRIBE_SECRET, c.req.query('t'))))
      return c.json({ error: 'invalid_token' }, 401);
    return notImplemented(c);
  });
}

export default route;
