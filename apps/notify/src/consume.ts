import { EMAIL_DAILY_CAP, utcDay } from '@ti/core/budget';

/** ti-notify. See docs/IMPLEMENTATION_PLAN.md §10. */
export interface Env {
  DB_SIGNALS: D1Database;
  DB_USERS: D1Database;
  RESEND_API_KEY: string;
  UNSUBSCRIBE_SECRET: string;
  EMAIL_FROM: string;
  APP_BASE: string;
}

interface ResendEmail {
  from: string;
  to: string[];
  subject: string;
  html: string;
  text: string;
  headers: Record<string, string>;
}

/** Resend batch API: up to 100 emails per call. Idempotency key prevents duplicate sends on retry. */
export async function sendBatch(env: Env, emails: ResendEmail[], idempotencyKey: string): Promise<void> {
  if (emails.length === 0) return;
  const res = await fetch('https://api.resend.com/emails/batch', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      'content-type': 'application/json',
      'idempotency-key': idempotencyKey,
    },
    body: JSON.stringify(emails),
  });
  if (!res.ok) throw new Error(`Resend batch failed: ${res.status}`);
}

/** Remaining sends today under the free-plan cap (95 of 100). */
export async function remainingToday(env: Env): Promise<number> {
  const row = await env.DB_USERS.prepare('SELECT sent FROM email_log WHERE day = ?1')
    .bind(utcDay())
    .first<{ sent: number }>();
  return Math.max(0, EMAIL_DAILY_CAP - (row?.sent ?? 0));
}

/** RFC 8058 one-click unsubscribe headers. */
export function unsubscribeHeaders(url: string): Record<string, string> {
  return { 'List-Unsubscribe': `<${url}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' };
}

export type NotifyMessage = { kind: 'run-finished'; at: number };

export async function consume(batch: MessageBatch<NotifyMessage>, _env: Env): Promise<void> {
  for (const msg of batch.messages) {
    // TODO(M3): load changes since cursor → match watch rows (alerts_on) → alert_queue
    //           → instant users now; daily/weekly digests on the 03:00 UTC run → sendBatch within cap.
    msg.ack();
  }
}
