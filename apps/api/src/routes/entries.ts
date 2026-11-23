import { getAuth } from '@hono/clerk-auth';
import { normaliseId } from '@ti/core/ids';
import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import { credits } from '../lib/credits';
import type { AppEnv } from '../lib/env';
import { notImplemented } from '../lib/not-implemented';
import { previewEntry } from '../lib/preview';
import { resolveKey } from '../lib/resolve-key';

const route = new Hono<AppEnv>();

route.get('/v1/entries/:id', async (c) => {
  const key = await resolveKey(c.env, normaliseId(c.req.param('id')));
  const row = await c.env.DB_VULNS.prepare('SELECT * FROM vulns WHERE key = ?1')
    .bind(key)
    .first<Record<string, unknown>>();
  if (!row) return c.json({ error: 'not_found' }, 404);
  const signedIn = Boolean(getAuth(c)?.userId);
  const entry = signedIn ? row : previewEntry(row);
  const sources = JSON.parse(String(row.sources ?? '[]')) as string[];
  c.header('cache-control', signedIn ? 'private, no-store' : 'public, max-age=300');
  return c.json({ access: signedIn ? 'full' : 'preview', entry, credits: credits(sources) });
});

// Signed in. Receipts with R2 keys and fetch times.
route.get('/v1/entries/:id/receipts', requireUser, notImplemented);

export default route;
