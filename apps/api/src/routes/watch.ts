import { MAX_WATCH_ITEMS, type WatchListResponse } from '@ti/core/account';
import { Hono } from 'hono';
import { z } from 'zod';
import {
  errorResponse,
  HttpError,
  noStore,
  parseBody,
  titlesFor,
  toWatchItem,
  type WatchRow,
} from '../lib/account';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { resolveKey, validId } from '../lib/resolve-key';

const route = new Hono<AppEnv>();
route.use('/v1/me/watch', noStore);
route.use('/v1/me/watch/*', noStore);

const PutBody = z.object({ alertsOn: z.boolean().optional() }).strict();

route.get('/v1/me/watch', requireUser, async (c) => {
  const { results } = await c.env.DB_USERS.prepare(
    'SELECT entry_key, alerts_on, created_at FROM watch WHERE user_id = ?1 ORDER BY created_at DESC, entry_key LIMIT ?2',
  )
    .bind(c.get('userId'), MAX_WATCH_ITEMS)
    .all<WatchRow>();
  const titles = await titlesFor(
    c.env,
    results.map((r) => r.entry_key),
  );
  const res: WatchListResponse = {
    items: results.map((r) => toWatchItem(r, titles.get(r.entry_key) ?? r.entry_key)),
    limit: MAX_WATCH_ITEMS,
  };
  return c.json(res);
});

route.put('/v1/me/watch/:id', requireUser, async (c) => {
  try {
    const userId = c.get('userId');
    const raw = c.req.param('id');
    if (!validId(raw)) return c.json({ error: 'bad_id' }, 400);
    const body = await parseBody(c, PutBody, { optional: true });
    const key = await resolveKey(c.env, raw);
    if (!key) return c.json({ error: 'not_found' }, 404);

    const select = () =>
      c.env.DB_USERS.prepare(
        'SELECT entry_key, alerts_on, created_at FROM watch WHERE user_id = ?1 AND entry_key = ?2',
      )
        .bind(userId, key)
        .first<WatchRow>();
    let row = await select();
    if (row) {
      if (body.alertsOn !== undefined) {
        await c.env.DB_USERS.prepare('UPDATE watch SET alerts_on = ?3 WHERE user_id = ?1 AND entry_key = ?2')
          .bind(userId, key, body.alertsOn ? 1 : 0)
          .run();
        row = { ...row, alerts_on: body.alertsOn ? 1 : 0 };
      }
    } else {
      await c.env.DB_USERS.prepare(
        `INSERT INTO watch (user_id, entry_key, created_at, alerts_on)
         SELECT ?1, ?2, ?3, ?4 WHERE (SELECT COUNT(*) FROM watch WHERE user_id = ?1) < ?5
         ON CONFLICT(user_id, entry_key) DO NOTHING`,
      )
        .bind(userId, key, new Date().toISOString(), body.alertsOn === false ? 0 : 1, MAX_WATCH_ITEMS)
        .run();
      row = await select();
      if (!row) throw new HttpError(409, 'limit_reached');
    }
    const title = (await titlesFor(c.env, [key])).get(key) ?? key;
    return c.json(toWatchItem(row, title));
  } catch (err) {
    return errorResponse(c, err);
  }
});

route.delete('/v1/me/watch/:id', requireUser, async (c) => {
  const raw = c.req.param('id');
  const id = validId(raw);
  if (!id) return c.json({ error: 'bad_id' }, 400);
  const resolved = await resolveKey(c.env, raw);
  const keys = resolved && resolved !== id ? [id, resolved] : [id];
  await c.env.DB_USERS.prepare(
    `DELETE FROM watch WHERE user_id = ?1 AND entry_key IN (${keys.map((_, i) => `?${i + 2}`).join(',')})`,
  )
    .bind(c.get('userId'), ...keys)
    .run();
  return c.json({ ok: true });
});

export default route;
