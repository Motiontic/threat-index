import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import app from '../src/index';

const SECRET = 'whsec_dGVzdC1zaWduaW5nLXNlY3JldA==';
const E = env as unknown as { DB_USERS: D1Database };

async function sign(secret: string, id: string, ts: string, body: string): Promise<string> {
  const raw = Uint8Array.from(atob(secret.slice('whsec_'.length)), (ch) => ch.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${ts}.${body}`));
  return `v1,${btoa(String.fromCharCode(...new Uint8Array(mac)))}`;
}

let seq = 0;
async function post(
  event: unknown,
  opts: { id?: string; envOverride?: object; badSignature?: boolean } = {},
) {
  const body = JSON.stringify(event);
  const id = opts.id ?? `msg_test_${++seq}_${crypto.randomUUID()}`;
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = opts.badSignature
    ? 'v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    : await sign(SECRET, id, ts, body);
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request('https://api.test/webhooks/clerk', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'svix-id': id,
        'svix-timestamp': ts,
        'svix-signature': signature,
      },
      body,
    }),
    (opts.envOverride ?? env) as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return { res, id };
}

const created = (id: string, email: string, first = 'Ada') => ({
  type: 'user.created',
  data: {
    id,
    email_addresses: [{ id: 'e1', email_address: email, verification: { status: 'verified' } }],
    primary_email_address_id: 'e1',
    first_name: first,
    last_name: 'L',
  },
});
const deleted = (id: string) => ({ type: 'user.deleted', data: { id, deleted: true, object: 'user' } });

const count = async (table: string, col: string, id: string) =>
  (
    await E.DB_USERS.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${col} = ?1`)
      .bind(id)
      .first<{ n: number }>()
  )?.n;
const totalUsers = async () =>
  (await E.DB_USERS.prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>())?.n;
const totalEvents = async () =>
  (await E.DB_USERS.prepare('SELECT COUNT(*) AS n FROM webhook_events').first<{ n: number }>())?.n;

beforeEach(async () => {
  for (const t of ['users', 'watch', 'saved_searches', 'alert_queue', 'alerts_sent', 'webhook_events']) {
    await E.DB_USERS.prepare(`DELETE FROM ${t}`).run();
  }
});

describe('POST /webhooks/clerk', () => {
  it('user.created writes the row and records the svix-id', async () => {
    const { res, id } = await post(created('wh_1', 'a@example.test'));
    expect(res.status).toBe(200);
    const row = await E.DB_USERS.prepare("SELECT email, name FROM users WHERE id = 'wh_1'").first();
    expect(row).toEqual({ email: 'a@example.test', name: 'Ada L' });
    expect(await count('webhook_events', 'id', id)).toBe(1);
  });

  it('stores only a verified address: the verified primary first, else another verified one, else empty', async () => {
    const mk = (id: string, addrs: object[], primary: string) => ({
      type: 'user.created',
      data: {
        id,
        email_addresses: addrs,
        primary_email_address_id: primary,
        first_name: 'A',
        last_name: 'B',
      },
    });
    const ok = { status: 'verified' };
    const no = { status: 'unverified' };
    await post(
      mk(
        'wh_v1',
        [
          { id: 'e1', email_address: 'other@example.test', verification: ok },
          { id: 'e2', email_address: 'primary@example.test', verification: ok },
        ],
        'e2',
      ),
    );
    await post(
      mk(
        'wh_v2',
        [
          { id: 'e1', email_address: 'unverified@example.test', verification: no },
          { id: 'e2', email_address: 'fallback@example.test', verification: ok },
        ],
        'e1',
      ),
    );
    await post(mk('wh_v3', [{ id: 'e1', email_address: 'nope@example.test', verification: null }], 'e1'));
    const email = async (id: string) =>
      (await E.DB_USERS.prepare('SELECT email FROM users WHERE id = ?1').bind(id).first<{ email: string }>())
        ?.email;
    expect(await email('wh_v1')).toBe('primary@example.test');
    expect(await email('wh_v2')).toBe('fallback@example.test');
    expect(await email('wh_v3')).toBe('');
  });

  it('a replayed svix-id is a no-op', async () => {
    const first = await post(created('wh_2', 'a@example.test'));
    await E.DB_USERS.prepare("UPDATE users SET email = 'changed@example.test' WHERE id = 'wh_2'").run();
    const { res } = await post(created('wh_2', 'a@example.test'), { id: first.id });
    expect(res.status).toBe(200);
    expect(
      (await E.DB_USERS.prepare("SELECT email FROM users WHERE id = 'wh_2'").first<{ email: string }>())
        ?.email,
    ).toBe('changed@example.test');
    expect(await totalEvents()).toBe(1);
  });

  it('user.updated keeps display_name and alert settings', async () => {
    await post(created('wh_3', 'a@example.test'));
    await E.DB_USERS.prepare(
      "UPDATE users SET display_name = 'Mine', alert_instant = 1, digest = 'weekly' WHERE id = 'wh_3'",
    ).run();
    await post({ ...created('wh_3', 'b@example.test', 'Grace'), type: 'user.updated' });
    expect(
      await E.DB_USERS.prepare(
        "SELECT email, name, display_name, alert_instant, digest FROM users WHERE id = 'wh_3'",
      ).first(),
    ).toEqual({
      email: 'b@example.test',
      name: 'Grace L',
      display_name: 'Mine',
      alert_instant: 1,
      digest: 'weekly',
    });
  });

  it('user.deleted clears all of the user and none of another', async () => {
    for (const u of ['wh_a', 'wh_b']) {
      await E.DB_USERS.batch([
        E.DB_USERS.prepare("INSERT INTO users (id, email, created_at) VALUES (?1, 'x', 'x')").bind(u),
        E.DB_USERS.prepare(
          "INSERT INTO watch (user_id, entry_key, created_at) VALUES (?1, 'CVE-2099-0001', 'x')",
        ).bind(u),
        E.DB_USERS.prepare(
          "INSERT INTO saved_searches (user_id, id, label, query, created_at) VALUES (?1, 's', 'l', 'q', 'x')",
        ).bind(u),
        E.DB_USERS.prepare(
          "INSERT INTO alert_queue (user_id, change_id, created_at) VALUES (?1, 'c', 'x')",
        ).bind(u),
        E.DB_USERS.prepare(
          "INSERT INTO alerts_sent (user_id, change_id, sent_at) VALUES (?1, 'c', 'x')",
        ).bind(u),
      ]);
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const { res } = await post(deleted('wh_a'));
    expect(res.status).toBe(200);
    expect(fetchSpy).not.toHaveBeenCalled(); // it does not call Clerk
    fetchSpy.mockRestore();
    for (const [t, c] of [
      ['users', 'id'],
      ['watch', 'user_id'],
      ['saved_searches', 'user_id'],
      ['alert_queue', 'user_id'],
      ['alerts_sent', 'user_id'],
    ] as const) {
      expect([t, await count(t, c, 'wh_a')]).toEqual([t, 0]);
      expect([t, await count(t, c, 'wh_b')]).toEqual([t, 1]);
    }
  });

  it('a bad signature → 400, nothing written', async () => {
    const { res } = await post(created('wh_bad', 'a@example.test'), { badSignature: true });
    expect(res.status).toBe(400);
    expect(await totalUsers()).toBe(0);
    expect(await totalEvents()).toBe(0);
  });

  for (const secret of ['', undefined]) {
    it(`a correctly signed event with the secret set to ${JSON.stringify(secret)} → 400, nothing written`, async () => {
      const { res } = await post(created('wh_nosecret', 'a@example.test'), {
        envOverride: { ...env, CLERK_WEBHOOK_SIGNING_SECRET: secret },
      });
      expect(res.status).toBe(400);
      expect(await totalUsers()).toBe(0);
      expect(await totalEvents()).toBe(0);
    });
  }

  it('a handler failure → 500, no webhook_events row, so the retry runs', async () => {
    const failing = new Proxy(E.DB_USERS, {
      get(target, prop) {
        if (prop === 'batch') return () => Promise.reject(new Error('boom'));
        const v = Reflect.get(target, prop) as unknown;
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    });
    await E.DB_USERS.prepare("INSERT INTO users (id, email, created_at) VALUES ('wh_f', 'x', 'x')").run();
    const evt = deleted('wh_f');
    const first = await post(evt, { envOverride: { ...env, DB_USERS: failing } });
    expect(first.res.status).toBe(500);
    expect(await totalEvents()).toBe(0);
    expect(await count('users', 'id', 'wh_f')).toBe(1);
    const retry = await post(evt, { id: first.id });
    expect(retry.res.status).toBe(200);
    expect(await count('users', 'id', 'wh_f')).toBe(0);
    expect(await count('webhook_events', 'id', first.id)).toBe(1);
  });
});
