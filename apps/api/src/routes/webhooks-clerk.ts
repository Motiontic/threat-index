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
  const seen = await c.env.DB_USERS.prepare('SELECT 1 AS x FROM webhook_events WHERE id = ?1')
    .bind(svixId)
    .first();
  if (seen) return c.text('OK'); // retried delivery, already handled

  // Handle first, then record the id: a failed handler must not make Clerk's retry look like a duplicate.
  // Handlers are idempotent, so two concurrent deliveries of one event are harmless.
  try {
    await handle(c.env.DB_USERS, evt, now);
    await c.env.DB_USERS.prepare(
      'INSERT INTO webhook_events (id, source, received_at) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING',
    )
      .bind(svixId, 'clerk', now)
      .run();
  } catch {
    console.error('clerk webhook handler failed', evt.type);
    return c.text('Handler failed', 500);
  }
  return c.text('OK');
});

async function handle(db: D1Database, evt: Awaited<ReturnType<typeof verifySvix>>, now: string) {
  if (evt.type === 'user.created' || evt.type === 'user.updated') {
    const d = evt.data;
    // Only a verified address is stored (the primary one first), else ''. Alerts go to this address.
    const verified = d.email_addresses.filter((e) => e.verification?.status === 'verified');
    const primary = verified.find((e) => e.id === d.primary_email_address_id) ?? verified[0];
    const name = [d.first_name, d.last_name].filter(Boolean).join(' ') || null;
    await db
      .prepare(
        `INSERT INTO users (id, email, name, created_at, digest_weekday) VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(id) DO UPDATE SET email = excluded.email, name = excluded.name`,
      )
      .bind(d.id, primary?.email_address ?? '', name, now, new Date().getUTCDay())
      .run();
  }
  if (evt.type === 'user.deleted' && evt.data.id) await deleteUserData(db, evt.data.id);
}

export default route;
