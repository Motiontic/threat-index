import { EMAIL_DAILY_CAP, utcDay } from '@ti/core/budget';
import type { EmailKind } from '@ti/core/email';
import type { Deps, Env } from './env';
import type { PlannedEmail } from './plan';
import type { Rendered } from './render';

const RESEND_URL = 'https://api.resend.com/emails';

export interface Outgoing {
  planned: PlannedEmail;
  key: string;
  rendered: Rendered;
  /** Null for a watchlist change notice: it is a security notice, not an alert, and has no unsubscribe. */
  unsubscribeUrl: string | null;
  /** `watch_events` ids a change notice covers; marked notified once the email is sent. */
  eventIds?: string[];
}

export type SendStatus = 'sent' | 'dry_run' | 'failed';
export interface SendSummary {
  byKind: Partial<Record<EmailKind, Partial<Record<SendStatus, number>>>>;
  capReached: boolean;
  /** True when a 429, 5xx, timeout or network error stopped sending. */
  stopped: boolean;
}

/** RFC 8058 one-click unsubscribe headers. */
export function unsubscribeHeaders(url: string): Record<string, string> {
  return { 'List-Unsubscribe': `<${url}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' };
}

/** Sends left today under the cap. */
export async function remainingToday(env: Env, runAt: Date): Promise<number> {
  const row = await env.DB_USERS.prepare('SELECT sent FROM email_log WHERE day = ?1')
    .bind(utcDay(runAt))
    .first<{ sent: number }>();
  return Math.max(0, EMAIL_DAILY_CAP - (row?.sent ?? 0));
}

const iso = (deps: Deps) => new Date(deps.now()).toISOString();

async function reserveSlot(env: Env, day: string, cap: number): Promise<boolean> {
  await env.DB_USERS.prepare('INSERT INTO email_log (day, sent) VALUES (?1, 0) ON CONFLICT (day) DO NOTHING')
    .bind(day)
    .run();
  const res = await env.DB_USERS.prepare('UPDATE email_log SET sent = sent + 1 WHERE day = ?1 AND sent < ?2')
    .bind(day, cap)
    .run();
  return (res.meta.changes ?? 0) > 0;
}

const releaseSlot = (env: Env, day: string) =>
  env.DB_USERS.prepare('UPDATE email_log SET sent = MAX(0, sent - 1) WHERE day = ?1').bind(day).run();

async function finish(
  env: Env,
  deps: Deps,
  o: Outgoing,
  status: 'sent' | 'dry_run',
  providerId: string | null,
): Promise<void> {
  const now = iso(deps);
  const { userId, items } = o.planned;
  await env.DB_USERS.batch([
    env.DB_USERS.prepare(
      'UPDATE email_sends SET status = ?2, provider_id = COALESCE(?3, provider_id), error = NULL, updated_at = ?4 WHERE idem_key = ?1',
    ).bind(o.key, status, providerId, now),
    ...items.map((i) =>
      env.DB_USERS.prepare(
        'INSERT OR IGNORE INTO alerts_sent (user_id, change_id, sent_at) VALUES (?1, ?2, ?3)',
      ).bind(userId, i.changeId, now),
    ),
    ...items.map((i) =>
      env.DB_USERS.prepare('DELETE FROM alert_queue WHERE user_id = ?1 AND change_id = ?2').bind(
        userId,
        i.changeId,
      ),
    ),
    ...(o.eventIds ?? []).map((id) =>
      env.DB_USERS.prepare('UPDATE watch_events SET notified_at = ?2 WHERE id = ?1 AND user_id = ?3').bind(
        id,
        now,
        userId,
      ),
    ),
  ]);
}

async function markFailed(env: Env, deps: Deps, key: string, error: string): Promise<void> {
  await env.DB_USERS.prepare(
    "UPDATE email_sends SET status = 'failed', error = ?2, updated_at = ?3 WHERE idem_key = ?1",
  )
    .bind(key, error, iso(deps))
    .run();
}

/** Sends one email at a time, SEND_GAP_MS apart. Stops on the cap or on a retryable provider failure. */
export async function sendAll(
  env: Env,
  deps: Deps,
  runAt: Date,
  emails: Outgoing[],
  gapMs: number,
  /** Sends allowed today across all kinds, counted in `email_log`. Alerts pass less than the hard cap. */
  cap: number = EMAIL_DAILY_CAP,
): Promise<SendSummary> {
  const summary: SendSummary = { byKind: {}, capReached: false, stopped: false };
  const count = (kind: EmailKind, s: SendStatus) => {
    const k = summary.byKind[kind] ?? {};
    k[s] = (k[s] ?? 0) + 1;
    summary.byKind[kind] = k;
  };
  const day = utcDay(runAt);
  let calledResend = false;

  for (const o of emails) {
    const now = iso(deps);
    await env.DB_USERS.prepare(
      `INSERT INTO email_sends (idem_key, kind, change_count, status, created_at, updated_at)
       VALUES (?1, ?2, ?3, 'pending', ?4, ?4) ON CONFLICT (idem_key) DO NOTHING`,
    )
      .bind(o.key, o.planned.kind, o.eventIds?.length ?? o.planned.items.length, now)
      .run();
    const prior = await env.DB_USERS.prepare(
      'SELECT status, provider_id FROM email_sends WHERE idem_key = ?1',
    )
      .bind(o.key)
      .first<{ status: string; provider_id: string | null }>();
    if (prior?.status === 'sent' || prior?.status === 'dry_run') {
      await finish(env, deps, o, prior.status, null);
      count(o.planned.kind, prior.status);
      continue;
    }

    if (!(await reserveSlot(env, day, cap))) {
      summary.capReached = true;
      break;
    }

    if (!env.RESEND_API_KEY) {
      console.log(
        JSON.stringify({
          event: 'notify.dry_run',
          kind: o.planned.kind,
          items: o.planned.items.length,
          key: o.key,
        }),
      );
      await finish(env, deps, o, 'dry_run', null);
      count(o.planned.kind, 'dry_run');
      continue;
    }

    if (calledResend) await deps.sleep(gapMs);
    calledResend = true;
    let res: Response;
    try {
      res = await deps.fetch(RESEND_URL, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${env.RESEND_API_KEY}`,
          'content-type': 'application/json',
          'idempotency-key': o.key,
        },
        body: JSON.stringify({
          from: env.EMAIL_FROM,
          to: [o.planned.email],
          subject: o.rendered.subject,
          text: o.rendered.text,
          html: o.rendered.html,
          ...(o.unsubscribeUrl ? { headers: unsubscribeHeaders(o.unsubscribeUrl) } : {}),
        }),
        signal: AbortSignal.timeout(10_000),
      });
    } catch (e) {
      // Timeout or network error. Never log the error text: it can echo the request.
      await markFailed(env, deps, o.key, e instanceof Error ? e.name : 'network');
      await releaseSlot(env, day);
      count(o.planned.kind, 'failed');
      summary.stopped = true;
      break;
    }

    if (res.ok) {
      let providerId: string | null = null;
      try {
        const j = (await res.json()) as { id?: unknown };
        if (typeof j.id === 'string') providerId = j.id;
      } catch {}
      await finish(env, deps, o, 'sent', providerId);
      count(o.planned.kind, 'sent');
      continue;
    }
    await res.body?.cancel();
    await markFailed(env, deps, o.key, `http ${res.status}`);
    await releaseSlot(env, day);
    count(o.planned.kind, 'failed');
    if (res.status === 429 || res.status >= 500) {
      summary.stopped = true;
      break;
    }
  }
  return summary;
}
