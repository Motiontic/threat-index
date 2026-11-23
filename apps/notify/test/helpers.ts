import { env } from 'cloudflare:workers';
import { vi } from 'vitest';
import type { Env, NotifyMessage } from '../src/env';

export const E = env as unknown as Env;
export const MON_9 = new Date('2026-11-23T09:00:00.000Z'); // Monday
export const MON_3 = new Date('2026-11-23T03:00:00.000Z');
export const TUE_9 = new Date('2026-11-24T09:00:00.000Z');
export const T = (hhmm: string, day = '2026-11-23') => `${day}T${hhmm}:00.000Z`;

export const withKey = (): Env => ({ ...E, RESEND_API_KEY: 're_test' });

export async function reset(): Promise<void> {
  await E.DB_USERS.batch(
    [
      'users',
      'watch',
      'saved_searches',
      'alert_queue',
      'alerts_sent',
      'email_log',
      'email_sends',
      'notify_state',
    ].map((t) => E.DB_USERS.prepare(`DELETE FROM ${t}`)),
  );
  await E.DB_SIGNALS.prepare('DELETE FROM changes').run();
  await E.DB_VULNS.prepare('DELETE FROM vulns').run();
  await E.DB_WORLD.prepare('DELETE FROM companies').run();
}

export interface UserOpts {
  instant?: number;
  digest?: 'daily' | 'weekly' | 'off';
  weekday?: number;
  suppressed?: number;
  deleted?: string | null;
  triggers?: string;
  email?: string;
}
export async function seedUser(id: string, o: UserOpts = {}): Promise<void> {
  await E.DB_USERS.prepare(
    `INSERT INTO users (id, email, created_at, alert_instant, digest, digest_weekday, email_suppressed, deleted_at, alert_triggers)
     VALUES (?1, ?2, '2026-01-01T00:00:00.000Z', ?3, ?4, ?5, ?6, ?7, COALESCE(?8, '["newly_exploited","public_exploit","epss_band","fix_released","breach_notice"]'))`,
  )
    .bind(
      id,
      o.email ?? `${id}@example.com`,
      o.instant ?? 1,
      o.digest ?? 'off',
      o.weekday ?? 1,
      o.suppressed ?? 0,
      o.deleted ?? null,
      o.triggers ?? null,
    )
    .run();
}
export const seedWatch = (user: string, key: string, alertsOn = 1) =>
  E.DB_USERS.prepare(
    "INSERT INTO watch (user_id, entry_key, created_at, alerts_on) VALUES (?1, ?2, '2026-01-01T00:00:00.000Z', ?3)",
  )
    .bind(user, key, alertsOn)
    .run();
export const seedSearch = (user: string, id: string, query: string, params: object, alertsOn = 1) =>
  E.DB_USERS.prepare(
    "INSERT INTO saved_searches (user_id, id, label, query, created_at, params, alerts_on) VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00.000Z', ?5, ?6)",
  )
    .bind(user, id, `Search ${id}`, query, JSON.stringify(params), alertsOn)
    .run();
export const seedChange = (id: string, key: string, kind: string, at: string, source = 'osv') =>
  E.DB_SIGNALS.prepare(
    'INSERT INTO changes (id, entity_key, kind, old, new, at, source) VALUES (?1,?2,?3,?4,?5,?6,?7)',
  )
    .bind(
      id,
      key,
      kind,
      kind === 'cvss_change' ? '5.0' : null,
      kind === 'newly_exploited' ? '2026-11-20' : null,
      at,
      source,
    )
    .run();
export const seedVuln = (
  key: string,
  title: string,
  o: { cvss?: number; kev?: string; summary?: string } = {},
) =>
  E.DB_VULNS.prepare(
    "INSERT INTO vulns (key, kind, title, summary, published, modified, cvss, kev_added) VALUES (?1,'vuln',?2,?3,'2026-11-01','2026-11-20T00:00:00.000Z',?4,?5)",
  )
    .bind(key, title, o.summary ?? null, o.cvss ?? null, o.kev ?? null)
    .run();
export const seedEmailLog = (day: string, sent: number) =>
  E.DB_USERS.prepare('INSERT INTO email_log (day, sent) VALUES (?1, ?2)').bind(day, sent).run();

export const rows = async <R>(sql: string, ...binds: unknown[]): Promise<R[]> =>
  (
    await E.DB_USERS.prepare(sql)
      .bind(...binds)
      .all<R>()
  ).results;
export const queueOf = (user: string) =>
  rows<{ change_id: string; via: string }>(
    'SELECT change_id, via FROM alert_queue WHERE user_id = ?1 ORDER BY change_id',
    user,
  );

export interface Sent {
  url: string;
  headers: Record<string, string>;
  body: {
    from: string;
    to: string[];
    subject: string;
    text: string;
    html: string;
    headers: Record<string, string>;
  };
}
/** Answers only the Resend send URL; anything else is recorded in `bad` so the test can fail. */
export function fakeFetch(
  respond: (n: number, req: Sent) => Response = () => Response.json({ id: 're_id' }),
) {
  const sent: Sent[] = [];
  const bad: string[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url !== 'https://api.resend.com/emails') {
      bad.push(url);
      throw new Error(`unexpected fetch ${url}`);
    }
    const req: Sent = {
      url,
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body: JSON.parse(String(init?.body)),
    };
    sent.push(req);
    return respond(sent.length, req);
  }) as typeof fetch;
  return { fetch: fn, sent, bad, deps: { fetch: fn, sleep: async () => {} } };
}

export function fakeBatch(body: unknown) {
  const calls = { ack: 0, retry: [] as unknown[] };
  const batch = {
    messages: [
      {
        body,
        ack: () => void calls.ack++,
        retry: (o?: unknown) => void calls.retry.push(o),
      },
    ],
  } as unknown as MessageBatch<NotifyMessage>;
  return { batch, calls };
}

export function captureLogs() {
  const lines: string[] = [];
  const spy = vi
    .spyOn(console, 'log')
    .mockImplementation((...a: unknown[]) => void lines.push(a.map(String).join(' ')));
  return { lines, restore: () => spy.mockRestore() };
}
