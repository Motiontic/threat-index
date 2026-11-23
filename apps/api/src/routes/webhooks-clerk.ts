import { Hono } from 'hono';
import { verifySvix } from '../lib/auth';
import { deleteUserData } from '../lib/delete-user';
import type { AppEnv } from '../lib/env';

const route = new Hono<AppEnv>();

// Svix-signed, so this sits outside clerkMiddleware (which only covers /v1/*).
route.post('/webhooks/clerk', async (c) => {
  let evt: Awaited<ReturnType<typeof verifySvix>>;
  try {
    evt = await verifySvix(c, c.env.CLERK_WEBHOOK_SIGNING_SECRET);
  } catch {
    return c.text('Verification failed', 400);
  }
  const now = new Date().toISOString();
  const svixId = c.req.header('svix-id') ?? `${evt.type}:${now}`;
  const fresh = await c.env.DB_USERS.prepare(
    'INSERT INTO webhook_events (id, source, received_at) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING',
  )
    .bind(svixId, 'clerk', now)
    .run();
  if ((fresh.meta.changes ?? 0) === 0) return c.text('OK'); // retried delivery, already handled

  if (evt.type === 'user.created' || evt.type === 'user.updated') {
    const d = evt.data;
    const primary =
      d.email_addresses.find((e) => e.id === d.primary_email_address_id) ?? d.email_addresses[0];
    const name = [d.first_name, d.last_name].filter(Boolean).join(' ') || null;
    await c.env.DB_USERS.prepare(
      `INSERT INTO users (id, email, name, created_at, digest_weekday) VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(id) DO UPDATE SET email = excluded.email, name = excluded.name`,
    )
      .bind(d.id, primary?.email_address ?? '', name, now, new Date().getUTCDay())
      .run();
  }
  if (evt.type === 'user.deleted' && evt.data.id) await deleteUserData(c.env.DB_USERS, evt.data.id);
  return c.text('OK');
});

export default route;
