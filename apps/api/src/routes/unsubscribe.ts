import { verifyUnsubscribeToken } from '@ti/core/unsubscribe';
import { Hono } from 'hono';
import type { AppEnv } from '../lib/env';
import { applyUnsubscribe, renderPage } from '../lib/unsubscribe';

const route = new Hono<AppEnv>();

const HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";

function harden(c: { header: (k: string, v: string) => void }, html: boolean) {
  c.header('Cache-Control', 'no-store');
  c.header('Referrer-Policy', 'no-referrer'); // the token is in the URL
  c.header('X-Content-Type-Options', 'nosniff');
  if (html) c.header('Content-Security-Policy', HTML_CSP);
}

// GET shows a confirmation and writes nothing (mail scanners prefetch links).
route.get('/unsubscribe', async (c) => {
  const token = c.req.query('t');
  const p = await verifyUnsubscribeToken(c.env.UNSUBSCRIBE_SECRET, token);
  harden(c, true);
  if (!p) return c.html(renderPage('invalid'), 401);
  return c.html(renderPage('confirm', p, token), 200);
});

// POST is the RFC 8058 one-click and the page's button. The token comes from the query only.
route.post('/unsubscribe', async (c) => {
  const p = await verifyUnsubscribeToken(c.env.UNSUBSCRIBE_SECRET, c.req.query('t'));
  if (!p) {
    harden(c, false);
    return c.json({ error: 'invalid_token' }, 401);
  }
  try {
    await applyUnsubscribe(c.env.DB_USERS, p);
  } catch {
    console.error(JSON.stringify({ route: 'unsubscribe', scope: p.scope, applied: false }));
    harden(c, false);
    return c.json({ error: 'internal' }, 500);
  }
  console.log(JSON.stringify({ route: 'unsubscribe', scope: p.scope, applied: true }));
  harden(c, true);
  return c.html(renderPage('done', p), 200);
});

export default route;
