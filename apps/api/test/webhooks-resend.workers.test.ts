import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import app from '../src/index';

const E = env as unknown as { DB_USERS: D1Database };
const SECRET = 'whsec_dGVzdC1yZXNlbmQtc2VjcmV0';

async function sign(secret: string, id: string, ts: string, body: string): Promise<string> {
  const raw = Uint8Array.from(atob(secret.slice('whsec_'.length)), (ch) => ch.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${ts}.${body}`));
  return `v1,${btoa(String.fromCharCode(...new Uint8Array(mac)))}`;
}

let seq = 0;
async function post(body: string, opts: { id?: string; e?: object; badSignature?: boolean } = {}) {
  const id = opts.id ?? `msg_resend_${++seq}_${crypto.randomUUID()}`;
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = opts.badSignature
    ? 'v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    : await sign(SECRET, id, ts, body);
  const res = await app.fetch(
    new Request('https://api.test/webhooks/resend', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'svix-id': id,
        'svix-timestamp': ts,
        'svix-signature': signature,
      },
      body,
    }),
    (opts.e ?? env) as never,
    { waitUntil() {}, passThroughException() {} } as unknown as ExecutionContext,
  );
  return { res, id };
}

const suppressed = async (id: string) =>
  (
    await E.DB_USERS.prepare('SELECT email_suppressed AS s FROM users WHERE id = ?1')
      .bind(id)
      .first<{ s: number }>()
  )?.s;
const events = async () =>
  (
    await E.DB_USERS.prepare("SELECT COUNT(*) AS n FROM webhook_events WHERE source = 'resend'").first<{
      n: number;
    }>()
  )?.n;
const allEvents = async () =>
  (await E.DB_USERS.prepare('SELECT COUNT(*) AS n FROM webhook_events').first<{ n: number }>())?.n;

beforeEach(async () => {
  for (const t of ['users', 'webhook_events']) await E.DB_USERS.prepare(`DELETE FROM ${t}`).run();
  const ins = E.DB_USERS.prepare(
    "INSERT INTO users (id, email, created_at) VALUES (?1, ?2, '2025-01-01T00:00:00Z')",
  );
  await ins.bind('bounced', 'Bounced.User@Example.com').run();
  await ins.bind('soft', 'soft.user@example.com').run();
  await ins.bind('complainer', 'complainer@example.com').run();
  await ins.bind('delivered', 'delivered.user@example.com').run();
  await ins.bind('other', 'other@example.com').run();
});

describe('POST /webhooks/resend', () => {
  it('a permanent bounce suppresses the matching user (any case) and records the event', async () => {
    const { res, id } = await post(fixture('resend', 'bounced-permanent.json'));
    expect(res.status).toBe(200);
    expect(await suppressed('bounced')).toBe(1);
    expect(await suppressed('other')).toBe(0);
    const row = await E.DB_USERS.prepare('SELECT source FROM webhook_events WHERE id = ?1').bind(id).first();
    expect(row).toEqual({ source: 'resend' });
  });

  it('a bounce with no bounce object suppresses; a string `to` is accepted', async () => {
    const evt = JSON.parse(fixture('resend', 'bounced-permanent.json'));
    evt.data.bounce = undefined;
    evt.data.to = 'other@example.com';
    expect((await post(JSON.stringify(evt))).res.status).toBe(200);
    expect(await suppressed('other')).toBe(1);
  });

  it('transient bounce and delivered change nothing; complaint suppresses', async () => {
    for (const f of ['bounced-transient.json', 'delivered.json']) {
      expect((await post(fixture('resend', f))).res.status).toBe(200);
    }
    expect(await suppressed('soft')).toBe(0);
    expect(await suppressed('delivered')).toBe(0);
    expect(await events()).toBe(2);
    expect((await post(fixture('resend', 'complained.json'))).res.status).toBe(200);
    expect(await suppressed('complainer')).toBe(1);
  });

  it('a replayed svix-id does nothing', async () => {
    const body = fixture('resend', 'bounced-permanent.json');
    const first = await post(body);
    expect(await suppressed('bounced')).toBe(1);
    await E.DB_USERS.prepare("UPDATE users SET email_suppressed = 0 WHERE id = 'bounced'").run();
    const replay = await post(body, { id: first.id });
    expect(replay.res.status).toBe(200);
    expect(await suppressed('bounced')).toBe(0);
    expect(await events()).toBe(1);
  });

  it('rejects a bad signature or a missing secret, writing nothing', async () => {
    const body = fixture('resend', 'bounced-permanent.json');
    expect((await post(body, { badSignature: true })).res.status).toBe(400);
    expect((await post(body, { e: { ...env, RESEND_WEBHOOK_SECRET: '' } })).res.status).toBe(400);
    expect(await suppressed('bounced')).toBe(0);
    expect(await allEvents()).toBe(0);
  });

  it('an unknown address or a malformed body is a 200 with no change', async () => {
    const evt = JSON.parse(fixture('resend', 'bounced-permanent.json'));
    evt.data.to = ['nobody@example.com'];
    expect((await post(JSON.stringify(evt))).res.status).toBe(200);
    const bodies = [
      { type: 'email.bounced' },
      { type: 'email.complained', data: { to: 7 } },
      { type: 'email.complained', data: { to: ['a@example.com', 3] } },
      { type: 'email.complained', data: null },
      [],
    ];
    for (const b of bodies) expect((await post(JSON.stringify(b))).res.status).toBe(200);
    expect(
      (
        await E.DB_USERS.prepare('SELECT COUNT(*) AS n FROM users WHERE email_suppressed = 1').first<{
          n: number;
        }>()
      )?.n,
    ).toBe(0);
  });

  it('a handler failure is a 500 and records no event', async () => {
    const stub = {
      prepare: (sql: string) => ({
        bind: () => ({ first: async () => null, run: async () => ({}) }),
        sql,
      }),
      batch: async () => {
        throw new Error('boom');
      },
    };
    const { res } = await post(fixture('resend', 'bounced-permanent.json'), {
      e: { ...env, DB_USERS: stub },
    });
    expect(res.status).toBe(500);
    expect(await allEvents()).toBe(0);
    expect(await suppressed('bounced')).toBe(0);
  });
});
