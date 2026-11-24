import { env } from 'cloudflare:workers';
import { signUnsubscribeToken, type UnsubscribePayload } from '@ti/core/unsubscribe';
import { beforeEach, describe, expect, it } from 'vitest';
import app from '../src/index';

const E = env as unknown as { DB_USERS: D1Database };
const SECRET = 'test-unsubscribe-secret';
const NOW = 1700000000;

const call = (path: string, init?: RequestInit, e: object = env) =>
  app.fetch(
    new Request(`https://api.test${path}`, init),
    e as never,
    {
      waitUntil() {},
      passThroughException() {},
    } as unknown as ExecutionContext,
  );

const tok = (p: Omit<UnsubscribePayload, 'issuedAt'>, secret = SECRET) =>
  signUnsubscribeToken(secret, { ...p, issuedAt: NOW } as UnsubscribePayload);

async function state() {
  const q = async (sql: string) => (await E.DB_USERS.prepare(sql).all()).results;
  return {
    users: await q('SELECT id, alert_instant, digest, email_suppressed FROM users ORDER BY id'),
    watch: await q('SELECT user_id, entry_key, alerts_on FROM watch ORDER BY user_id, entry_key'),
    searches: await q('SELECT user_id, id, alerts_on FROM saved_searches ORDER BY user_id, id'),
  };
}

beforeEach(async () => {
  for (const t of ['users', 'watch', 'saved_searches', 'webhook_events']) {
    await E.DB_USERS.prepare(`DELETE FROM ${t}`).run();
  }
  for (const id of ['u1', 'u2']) {
    await E.DB_USERS.prepare(
      "INSERT INTO users (id, email, created_at, alert_instant, digest) VALUES (?1, ?2, '2025-01-01T00:00:00Z', 1, 'weekly')",
    )
      .bind(id, `${id}@example.test`)
      .run();
    for (const k of ['CVE-1', 'CVE-2']) {
      await E.DB_USERS.prepare(
        "INSERT INTO watch (user_id, entry_key, created_at, alerts_on) VALUES (?1, ?2, 'x', 1)",
      )
        .bind(id, k)
        .run();
    }
    for (const s of ['s1', 's2']) {
      await E.DB_USERS.prepare(
        "INSERT INTO saved_searches (user_id, id, label, query, created_at, alerts_on) VALUES (?1, ?2, 'l', 'q', 'x', 1)",
      )
        .bind(id, s)
        .run();
    }
  }
});

const post = (t: string, init: RequestInit = {}) => call(`/unsubscribe?t=${t}`, { method: 'POST', ...init });

describe('GET /unsubscribe', () => {
  it('shows the confirmation with hardening headers and writes nothing', async () => {
    const before = await state();
    const t = await tok({ userId: 'u1', scope: 'all' });
    const res = await call(`/unsubscribe?t=${t}`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain(`<form method="post" action="/unsubscribe?t=${t}">`);
    expect(html).toContain('lang="en"');
    expect(html).not.toContain('<script');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe(
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    );
    expect(await state()).toEqual(before);
  });

  it('escapes an item in the page', async () => {
    const t = await tok({ userId: 'u1', scope: 'watch', item: '<script>alert(1)</script>' });
    const html = await (await call(`/unsubscribe?t=${t}`)).text();
    expect(html).not.toContain('<script>alert');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });
});

describe('POST /unsubscribe', () => {
  it('all: turns off instant and digest only', async () => {
    const res = await post(await tok({ userId: 'u1', scope: 'all' }));
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.text()).toContain('all MTI alert email');
    const s = await state();
    expect(s.users).toEqual([
      { id: 'u1', alert_instant: 0, digest: 'off', email_suppressed: 0 },
      { id: 'u2', alert_instant: 1, digest: 'weekly', email_suppressed: 0 },
    ]);
    expect(s.watch.every((r) => r.alerts_on === 1)).toBe(true);
    expect(s.searches.every((r) => r.alerts_on === 1)).toBe(true);
  });

  it('digest: only digest', async () => {
    await post(await tok({ userId: 'u1', scope: 'digest' }));
    expect((await state()).users).toEqual([
      { id: 'u1', alert_instant: 1, digest: 'off', email_suppressed: 0 },
      { id: 'u2', alert_instant: 1, digest: 'weekly', email_suppressed: 0 },
    ]);
  });

  it('watch: only that entry for that user', async () => {
    await post(await tok({ userId: 'u1', scope: 'watch', item: 'CVE-1' }));
    const s = await state();
    expect(s.watch.filter((r) => r.alerts_on === 0)).toEqual([
      { user_id: 'u1', entry_key: 'CVE-1', alerts_on: 0 },
    ]);
    expect(s.users.every((u) => u.digest === 'weekly' && u.alert_instant === 1)).toBe(true);
    expect(s.searches.every((r) => r.alerts_on === 1)).toBe(true);
  });

  it('search: only that saved search for that user', async () => {
    await post(await tok({ userId: 'u1', scope: 'search', item: 's2' }));
    const s = await state();
    expect(s.searches.filter((r) => r.alerts_on === 0)).toEqual([{ user_id: 'u1', id: 's2', alerts_on: 0 }]);
    expect(s.watch.every((r) => r.alerts_on === 1)).toBe(true);
  });

  it('is idempotent and tolerates missing users and items', async () => {
    const t = await tok({ userId: 'u1', scope: 'all' });
    expect((await post(t)).status).toBe(200);
    const once = await state();
    expect((await post(t)).status).toBe(200);
    expect(await state()).toEqual(once);

    const before = await state();
    expect((await post(await tok({ userId: 'gone', scope: 'all' }))).status).toBe(200);
    expect((await post(await tok({ userId: 'u2', scope: 'watch', item: 'CVE-404' }))).status).toBe(200);
    expect((await post(await tok({ userId: 'u2', scope: 'search', item: 'nope' }))).status).toBe(200);
    expect(await state()).toEqual(before);
  });

  it('applies the one-click body mail clients send, and no body', async () => {
    const r1 = await post(await tok({ userId: 'u1', scope: 'digest' }), {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'List-Unsubscribe=One-Click',
    });
    expect(r1.status).toBe(200);
    const r2 = await post(await tok({ userId: 'u2', scope: 'digest' }));
    expect(r2.status).toBe(200);
    expect((await state()).users.map((u) => u.digest)).toEqual(['off', 'off']);
  });
});

describe('bad tokens', () => {
  it('GET 401 HTML and POST 401 JSON, nothing written', async () => {
    const before = await state();
    const good = await tok({ userId: 'u1', scope: 'all' });
    const bad = [
      await tok({ userId: 'u1', scope: 'all' }, 'wrong-secret'),
      `${good.slice(0, 5)}${good[5] === 'A' ? 'B' : 'A'}${good.slice(6)}`,
      'nope',
    ];
    for (const t of bad) {
      const g = await call(`/unsubscribe?t=${t}`);
      expect(g.status).toBe(401);
      expect(g.headers.get('content-type')).toContain('text/html');
      expect(g.headers.get('cache-control')).toBe('no-store');
      const p = await post(t);
      expect(p.status).toBe(401);
      expect(await p.json()).toEqual({ error: 'invalid_token' });
    }
    expect((await call('/unsubscribe')).status).toBe(401);
    expect(await state()).toEqual(before);
  });

  it('an empty UNSUBSCRIBE_SECRET fails closed', async () => {
    const before = await state();
    const t = await tok({ userId: 'u1', scope: 'all' });
    const e = { ...env, UNSUBSCRIBE_SECRET: '' };
    expect((await call(`/unsubscribe?t=${t}`, undefined, e)).status).toBe(401);
    expect((await call(`/unsubscribe?t=${t}`, { method: 'POST' }, e)).status).toBe(401);
    expect(await state()).toEqual(before);
  });
});
