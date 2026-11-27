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
import {
  eventAfterChange,
  mcpOf,
  removalCapSql,
  removalCut,
  removalLimitResponse,
} from '../lib/watch-events';

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
    const mcp = mcpOf(c);
    // An MCP caller may turn alerts on, never off: a stolen token must not silence them.
    if (mcp && body.alertsOn === false) throw new HttpError(403, 'not_allowed_for_mcp');
    const db = c.env.DB_USERS;
    const stmts = [
      db
        .prepare(
          `INSERT INTO watch (user_id, entry_key, created_at, alerts_on)
           SELECT ?1, ?2, ?3, ?4 WHERE (SELECT COUNT(*) FROM watch WHERE user_id = ?1) < ?5
           ON CONFLICT(user_id, entry_key) DO NOTHING`,
        )
        .bind(userId, key, new Date().toISOString(), body.alertsOn === false ? 0 : 1, MAX_WATCH_ITEMS),
    ];
    if (mcp) stmts.push(eventAfterChange(db, mcp, 'add', `entry:${key}`));
    if (body.alertsOn !== undefined) {
      stmts.push(
        db
          .prepare(
            'UPDATE watch SET alerts_on = ?3 WHERE user_id = ?1 AND entry_key = ?2 AND alerts_on != ?3',
          )
          .bind(userId, key, body.alertsOn ? 1 : 0),
      );
      if (mcp) stmts.push(eventAfterChange(db, mcp, 'alerts_on', `entry:${key}`));
    }
    const created = ((await db.batch(stmts))[0]?.meta.changes ?? 0) > 0;
    const row = await select();
    if (!row) throw new HttpError(409, 'limit_reached');
    const title = (await titlesFor(c.env, [key])).get(key) ?? key;
    return c.json({ ...toWatchItem(row, title), created });
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
  const userId = c.get('userId');
  const mcp = mcpOf(c);
  const db = c.env.DB_USERS;
  // Which of the candidate keys the user actually watches: one delete, and one `remove` event, per such key.
  const held = (
    await db
      .prepare(
        `SELECT entry_key FROM watch WHERE user_id = ?1 AND entry_key IN (${keys.map((_, i) => `?${i + 2}`).join(',')})`,
      )
      .bind(userId, ...keys)
      .all<{ entry_key: string }>()
  ).results.map((r) => r.entry_key);
  // ?2 is the 24-hour cut, used by the MCP removal cap.
  const del = db.prepare(
    `DELETE FROM watch WHERE user_id = ?1 AND entry_key = ?3${mcp ? ` AND ${removalCapSql('?2')}` : ' AND ?2 IS NOT NULL'}`,
  );
  const stmts: D1PreparedStatement[] = [];
  const delAt: number[] = [];
  for (const k of held) {
    delAt.push(stmts.length);
    stmts.push(del.bind(userId, removalCut(), k));
    if (mcp) stmts.push(eventAfterChange(db, mcp, 'remove', `entry:${k}`));
  }
  const results = stmts.length > 0 ? await db.batch(stmts) : [];
  const removed = delAt.some((i) => (results[i]?.meta.changes ?? 0) > 0);
  if (!removed && mcp) {
    const exists = await db
      .prepare(
        `SELECT 1 AS x FROM watch WHERE user_id = ?1 AND entry_key IN (${keys.map((_, i) => `?${i + 2}`).join(',')})`,
      )
      .bind(userId, ...keys)
      .first();
    if (exists) return removalLimitResponse(c, userId);
  }
  return c.json({ ok: true, removed });
});

export default route;
