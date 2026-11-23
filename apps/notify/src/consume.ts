import { utcDay } from '@ti/core/budget';
import { emailIdempotencyKey } from '@ti/core/email';
import { signUnsubscribeToken, UNSUBSCRIBE_PATH, type UnsubscribeScope } from '@ti/core/unsubscribe';
import { type Change, collect } from './collect';
import type { Deps, Env, NotifyMessage } from './env';
import {
  D1_CHUNK,
  DAY_MS,
  DIGEST_HOUR_UTC,
  MAX_QUEUE_ROWS,
  QUEUE_TTL_DAYS,
  SEND_GAP_MS,
  SENT_TTL_DAYS,
} from './limits';
import { loadDocs, matchAndQueue } from './match';
import { type PlannedEmail, plan, type QueueRow } from './plan';
import { renderEmail } from './render';
import { type Outgoing, remainingToday, sendAll } from './send';

export type { Env, NotifyMessage } from './env';

const defaultDeps: Deps = {
  fetch: (input, init) => globalThis.fetch(input, init),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => Date.now(),
};

const marks = (n: number) => Array.from({ length: n }, (_, i) => `?${i + 1}`).join(',');
function chunks<T>(xs: T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += D1_CHUNK) out.push(xs.slice(i, i + D1_CHUNK));
  return out;
}

async function loadQueue(env: Env): Promise<QueueRow[]> {
  const rows = (
    await env.DB_USERS.prepare(
      `SELECT q.user_id, q.change_id, q.via, q.created_at, u.email, u.alert_instant, u.digest, u.digest_weekday,
              u.email_suppressed, u.deleted_at
       FROM alert_queue q JOIN users u ON u.id = q.user_id ORDER BY q.created_at, q.user_id, q.change_id LIMIT ?1`,
    )
      .bind(MAX_QUEUE_ROWS)
      .all<{
        user_id: string;
        change_id: string;
        via: string;
        created_at: string;
        email: string | null;
        alert_instant: number;
        digest: string;
        digest_weekday: number;
        email_suppressed: number;
        deleted_at: string | null;
      }>()
  ).results;
  return rows.map((r) => ({
    userId: r.user_id,
    changeId: r.change_id,
    via: r.via,
    createdAt: r.created_at,
    email: r.email ?? '',
    alertInstant: r.alert_instant,
    digest: r.digest,
    digestWeekday: r.digest_weekday,
    suppressed: r.email_suppressed,
    deleted: r.deleted_at,
  }));
}

async function loadChanges(env: Env, ids: string[]): Promise<Map<string, Change>> {
  const out = new Map<string, Change>();
  for (const part of chunks(ids)) {
    const rows = (
      await env.DB_SIGNALS.prepare(
        `SELECT id, entity_key, kind, old, new, at, source FROM changes WHERE id IN (${marks(part.length)})`,
      )
        .bind(...part)
        .all<Change>()
    ).results;
    for (const c of rows) out.set(c.id, c);
  }
  return out;
}

async function loadLabels(env: Env, userIds: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>(); // `${userId}:${searchId}` → label
  for (const part of chunks(userIds)) {
    const rows = (
      await env.DB_USERS.prepare(
        `SELECT user_id, id, label FROM saved_searches WHERE user_id IN (${marks(part.length)})`,
      )
        .bind(...part)
        .all<{ user_id: string; id: string; label: string }>()
    ).results;
    for (const r of rows) out.set(`${r.user_id}:${r.id}`, r.label);
  }
  return out;
}

function scopeFor(e: PlannedEmail): { scope: UnsubscribeScope; item?: string } {
  if (e.kind !== 'instant') return { scope: 'digest' };
  const keys = new Set(e.items.map((i) => i.change.entity_key));
  const only = keys.size === 1 ? [...keys][0] : undefined;
  return only ? { scope: 'watch', item: only } : { scope: 'all' };
}

async function prune(env: Env, runAt: Date): Promise<void> {
  const ago = (days: number) => new Date(runAt.getTime() - days * DAY_MS);
  const sentCut = ago(SENT_TTL_DAYS);
  await env.DB_USERS.batch([
    env.DB_USERS.prepare('DELETE FROM alert_queue WHERE created_at < ?1').bind(
      ago(QUEUE_TTL_DAYS).toISOString(),
    ),
    env.DB_USERS.prepare('DELETE FROM alerts_sent WHERE sent_at < ?1').bind(sentCut.toISOString()),
    env.DB_USERS.prepare('DELETE FROM email_sends WHERE created_at < ?1').bind(sentCut.toISOString()),
    env.DB_USERS.prepare('DELETE FROM email_log WHERE day < ?1').bind(utcDay(sentCut)),
  ]);
}

/** One notify run, decided by `runAt` (the cron time), not the wall clock. */
export async function runNotify(env: Env, runAt: Date, deps: Partial<Deps> = {}): Promise<void> {
  const d: Deps = { ...defaultDeps, ...deps };

  // 1–2. Collect and match.
  const got = await collect(env, runAt);
  if (got.backlog) console.log(JSON.stringify({ event: 'notify.backlog', read: got.forwardCount }));
  const queued = await matchAndQueue(env, got.changes, got.cursor, runAt);

  // 3. Plan.
  const rows = await loadQueue(env);
  const changes = await loadChanges(env, [...new Set(rows.map((r) => r.changeId))]);
  const { emails, drop } = plan(rows, changes, runAt);
  for (let i = 0; i < drop.length; i += D1_CHUNK)
    await env.DB_USERS.batch(
      drop
        .slice(i, i + D1_CHUNK)
        .map((r) =>
          env.DB_USERS.prepare('DELETE FROM alert_queue WHERE user_id = ?1 AND change_id = ?2').bind(
            r.userId,
            r.changeId,
          ),
        ),
    );

  // 4–5. Render and send.
  let summary: { byKind: object; capReached: boolean; stopped: boolean } = {
    byKind: {},
    capReached: false,
    stopped: false,
  };
  if (emails.length > 0) {
    if (!env.UNSUBSCRIBE_SECRET) {
      console.log(JSON.stringify({ event: 'notify.no_unsubscribe_secret', pending: emails.length }));
    } else {
      const docs = await loadDocs(
        env,
        emails.flatMap((e) => e.items.map((i) => i.change)),
      );
      const labels = await loadLabels(env, [...new Set(emails.map((e) => e.userId))]);
      const out: Outgoing[] = [];
      for (const e of emails) {
        const { scope, item } = scopeFor(e);
        const token = await signUnsubscribeToken(env.UNSUBSCRIBE_SECRET, {
          userId: e.userId,
          scope,
          ...(item === undefined ? {} : { item }),
          issuedAt: runAt.getTime(),
        });
        const unsubscribeUrl = `${env.API_BASE.replace(/\/+$/, '')}${UNSUBSCRIBE_PATH}?t=${token}`;
        const rendered = renderEmail({
          kind: e.kind,
          appBase: env.APP_BASE,
          unsubscribeUrl,
          items: e.items.map((i) => {
            const doc = docs.get(i.change.entity_key);
            return {
              change: i.change,
              title: doc?.title ?? i.change.entity_key,
              company: i.change.kind === 'breach_notice',
              group: i.via.startsWith('search:')
                ? (labels.get(`${e.userId}:${i.via.slice(7)}`) ?? 'a saved search')
                : null,
            };
          }),
        });
        const key = await emailIdempotencyKey(
          e.userId,
          e.kind,
          e.items.map((i) => i.changeId),
        );
        out.push({ planned: e, key, rendered, unsubscribeUrl });
      }
      summary = await sendAll(env, d, runAt, out, SEND_GAP_MS);
    }
  }

  // 6. Prune on the digest run.
  if (runAt.getUTCHours() === DIGEST_HOUR_UTC) await prune(env, runAt);

  console.log(
    JSON.stringify({
      event: 'notify.run',
      changes: got.changes.length,
      queued,
      emails: summary.byKind,
      capReached: summary.capReached,
      stopped: summary.stopped,
      capLeft: await remainingToday(env, runAt),
    }),
  );
}

function parseMessage(body: unknown, nowMs: number): { at: number } | null {
  if (typeof body !== 'object' || body === null) return null;
  const m = body as Record<string, unknown>;
  if (m.kind !== 'run-finished') return null;
  if (typeof m.at !== 'number' || !Number.isFinite(m.at)) return null;
  if (Math.abs(m.at - nowMs) > 365 * DAY_MS) return null;
  return { at: m.at };
}

export async function consume(
  batch: MessageBatch<NotifyMessage>,
  env: Env,
  deps: Partial<Deps> = {},
): Promise<void> {
  for (const msg of batch.messages) {
    const parsed = parseMessage(msg.body, (deps.now ?? defaultDeps.now)());
    if (!parsed) {
      console.log(JSON.stringify({ event: 'notify.bad_message' }));
      msg.ack();
      continue;
    }
    try {
      await runNotify(env, new Date(parsed.at), deps);
      msg.ack();
    } catch (e) {
      console.log(
        JSON.stringify({ event: 'notify.run_failed', error: e instanceof Error ? e.name : 'error' }),
      );
      msg.retry({ delaySeconds: 300 });
    }
  }
}
