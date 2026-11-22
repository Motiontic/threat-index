import { verifyWebhook } from '@clerk/backend/webhooks';
import { clerkMiddleware, getAuth } from '@hono/clerk-auth';
import { NVD_NOTICE, normaliseId } from '@ti/core';
import { SOURCE_BY_ID } from '@ti/sources';
import { Hono, type MiddlewareHandler } from 'hono';

/**
 * ti-api. See docs/IMPLEMENTATION_PLAN.md §8.
 * Single-user accounts: we only ever read `userId` from Clerk, never `orgId`.
 * The sign-up gate is enforced here: visitors get preview fields only.
 */
type Bindings = {
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_USERS: D1Database;
  BUCKET: R2Bucket;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  CLERK_WEBHOOK_SIGNING_SECRET: string;
};
type Variables = { userId: string };
type AppEnv = { Bindings: Bindings; Variables: Variables };

const app = new Hono<AppEnv>();

app.get('/v1/health', (c) => c.json({ ok: true }));

// Webhooks are verified by signature, not by session, so they sit outside the Clerk middleware.
app.post('/webhooks/clerk', async (c) => {
  let evt: Awaited<ReturnType<typeof verifyWebhook>>;
  try {
    evt = await verifyWebhook(c.req.raw, { signingSecret: c.env.CLERK_WEBHOOK_SIGNING_SECRET });
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

app.use('/v1/*', clerkMiddleware());

const requireUser: MiddlewareHandler<AppEnv> = async (c, next) => {
  const userId = getAuth(c)?.userId;
  if (!userId) return c.json({ error: 'sign_in_required' }, 401);
  c.set('userId', userId);
  await next();
};

/** Fields a visitor may see. Everything else needs a free account. */
const PREVIEW_FIELDS = ['key', 'kind', 'title', 'summary', 'published', 'cvss', 'kev_added'] as const;

/** Which source owns an ID prefix, so any alias resolves through the advisories primary key. */
const PREFIX_SOURCE: [RegExp, string][] = [
  [/^GHSA-/, 'github-advisory-db'],
  [/^RHSA-/, 'red-hat'],
  [/^USN-/, 'ubuntu'],
  [/^(DSA|DLA)-/, 'debian'],
  [/^JVNDB-/, 'jvn'],
  [/^EUVD-/, 'enisa'],
  [/^(PYSEC|GO|RUSTSEC|MAL)-/, 'osv'],
];

async function resolveKey(env: Bindings, id: string): Promise<string> {
  const source = PREFIX_SOURCE.find(([re]) => re.test(id))?.[1];
  if (!source) return id;
  const row = await env.DB_ADVISORIES.prepare(
    'SELECT vuln_key FROM advisories WHERE source = ?1 AND source_id = ?2',
  )
    .bind(source, id)
    .first<{ vuln_key: string | null }>();
  return row?.vuln_key ?? id;
}

function credits(sourceIds: string[]): { source: string; text: string }[] {
  const out = sourceIds.map((id) => ({ source: id, text: SOURCE_BY_ID.get(id)?.credit ?? `Source: ${id}` }));
  if (sourceIds.includes('nvd') && !out.some((c) => c.text === NVD_NOTICE))
    out.push({ source: 'nvd', text: NVD_NOTICE });
  return out;
}

app.get('/v1/entries/:id', async (c) => {
  const key = await resolveKey(c.env, normaliseId(c.req.param('id')));
  const row = await c.env.DB_VULNS.prepare('SELECT * FROM vulns WHERE key = ?1')
    .bind(key)
    .first<Record<string, unknown>>();
  if (!row) return c.json({ error: 'not_found' }, 404);
  const signedIn = Boolean(getAuth(c)?.userId);
  const entry = signedIn ? row : Object.fromEntries(PREVIEW_FIELDS.map((f) => [f, row[f] ?? null]));
  const sources = JSON.parse(String(row.sources ?? '[]')) as string[];
  c.header('cache-control', signedIn ? 'private, no-store' : 'public, max-age=300');
  return c.json({ access: signedIn ? 'full' : 'preview', entry, credits: credits(sources) });
});

app.get('/v1/me/watch', requireUser, async (c) => {
  const { results } = await c.env.DB_USERS.prepare(
    'SELECT entry_key, alerts_on, created_at FROM watch WHERE user_id = ?1 ORDER BY created_at DESC',
  )
    .bind(c.get('userId'))
    .all();
  return c.json({ watch: results });
});

app.put('/v1/me/watch/:id', requireUser, async (c) => {
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

app.delete('/v1/me/watch/:id', requireUser, async (c) => {
  await c.env.DB_USERS.prepare('DELETE FROM watch WHERE user_id = ?1 AND entry_key = ?2')
    .bind(c.get('userId'), normaliseId(c.req.param('id')))
    .run();
  return c.json({ ok: true });
});

// TODO(M2): /v1/me (profile, alert settings, delete account via Clerk Backend API), saved searches,
// receipts, search (§8 search design), /unsubscribe, /webhooks/resend, /internal/jobs/:id/*.

async function deleteUserData(db: D1Database, userId: string): Promise<void> {
  await db.batch(
    ['watch', 'saved_searches', 'alert_queue', 'alerts_sent']
      .map((t) => db.prepare(`DELETE FROM ${t} WHERE user_id = ?1`).bind(userId))
      .concat(db.prepare('DELETE FROM users WHERE id = ?1').bind(userId)),
  );
}

export default app;
