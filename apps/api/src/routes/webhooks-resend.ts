import { Hono } from 'hono';
import { verifySvix } from '../lib/auth';
import type { AppEnv } from '../lib/env';
import { suppressAddresses } from '../lib/suppress';

const route = new Hono<AppEnv>();

/** Addresses to suppress for this event, or [] when it needs no action or the body is unusable. */
function addressesToSuppress(evt: unknown): string[] {
  if (typeof evt !== 'object' || evt === null) return [];
  const { type, data } = evt as { type?: unknown; data?: unknown };
  if (typeof data !== 'object' || data === null) return [];
  const d = data as { to?: unknown; bounce?: unknown };
  if (type === 'email.bounced') {
    if (typeof d.bounce === 'object' && d.bounce !== null) {
      if ((d.bounce as { type?: unknown }).type !== 'Permanent') return [];
    }
  } else if (type !== 'email.complained') return [];
  if (typeof d.to === 'string') return [d.to];
  if (Array.isArray(d.to) && d.to.every((x) => typeof x === 'string')) return d.to as string[];
  return [];
}

// Svix-signed, so this sits outside clerkMiddleware. Bounces and complaints suppress the address.
route.post('/webhooks/resend', async (c) => {
  let evt: unknown;
  try {
    evt = await verifySvix(c, c.env.RESEND_WEBHOOK_SECRET);
  } catch {
    return c.text('Verification failed', 400);
  }
  const now = new Date().toISOString();
  const type = (evt as { type?: unknown } | null)?.type;
  const svixId = c.req.header('svix-id') ?? `${String(type)}:${now}`;
  const db = c.env.DB_USERS;
  try {
    const seen = await db.prepare('SELECT 1 AS x FROM webhook_events WHERE id = ?1').bind(svixId).first();
    if (seen) return c.text('OK'); // retried delivery, already handled

    // Handle first, then record the id: a failed handler must not make Resend's retry look like a duplicate.
    const suppressed = await suppressAddresses(db, addressesToSuppress(evt));
    await db
      .prepare(
        'INSERT INTO webhook_events (id, source, received_at) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING',
      )
      .bind(svixId, 'resend', now)
      .run();
    console.log(JSON.stringify({ route: 'webhooks-resend', type: String(type), suppressed }));
  } catch {
    console.error(JSON.stringify({ route: 'webhooks-resend', type: String(type), error: 'handler_failed' }));
    return c.text('Handler failed', 500);
  }
  return c.text('OK');
});

export default route;
