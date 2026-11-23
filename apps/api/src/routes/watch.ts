import { normaliseId } from '@ti/core/ids';
import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import type { AppEnv } from '../lib/env';

const route = new Hono<AppEnv>();

route.get('/v1/me/watch', requireUser, async (c) => {
  const { results } = await c.env.DB_USERS.prepare(
    'SELECT entry_key, alerts_on, created_at FROM watch WHERE user_id = ?1 ORDER BY created_at DESC',
  )
    .bind(c.get('userId'))
    .all();
  return c.json({ watch: results });
});

route.put('/v1/me/watch/:id', requireUser, async (c) => {
  const body = await c.req.json<{ alertsOn?: boolean }>().catch(() => ({ alertsOn: true }));
  await c.env.DB_USERS.prepare(
    `INSERT INTO watch (user_id, entry_key, created_at, alerts_on) VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(user_id, entry_key) DO UPDATE SET alerts_on = excluded.alerts_on`,
  )
    .bind(
      c.get('userId'),
      normaliseId(c.req.param('id')),
      new Date().toISOString(),
      body.alertsOn === false ? 0 : 1,
    )
    .run();
  return c.json({ ok: true });
});

route.delete('/v1/me/watch/:id', requireUser, async (c) => {
  await c.env.DB_USERS.prepare('DELETE FROM watch WHERE user_id = ?1 AND entry_key = ?2')
    .bind(c.get('userId'), normaliseId(c.req.param('id')))
    .run();
  return c.json({ ok: true });
});

export default route;
