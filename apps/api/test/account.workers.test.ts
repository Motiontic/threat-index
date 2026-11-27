import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Same stub as public-api.workers.test.ts: `vi.mock('@hono/clerk-auth')` does not work in this pool, so
// the route modules are mounted on a test app whose middleware sets `clerkAuth` from a header.
const { Hono } = await import('hono');
const { default: me } = await import('../src/routes/me');
const { default: watch } = await import('../src/routes/watch');
const { default: savedSearches } = await import('../src/routes/saved-searches');
const app = new Hono();
app.use('/v1/*', async (c, next) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
  await next();
});
for (const r of [me, watch, savedSearches]) app.route('/', r as never);

const E = env as unknown as {
  DB_USERS: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  CLERK_SECRET_KEY: string;
};

async function call(
  method: string,
  path: string,
  opts: { user?: string; body?: unknown; raw?: string } = {},
) {
  const headers: Record<string, string> = {};
  if (opts.user) headers['x-test-user'] = opts.user;
  const init: RequestInit = { method, headers };
  if (opts.raw !== undefined) init.body = opts.raw;
  else if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const ctx = createExecutionContext();
  const res = await app.fetch(new Request(`https://api.test${path}`, init), env as never, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}
const json = async (res: Response) => (await res.json()) as any;

// Fake Clerk: answers only https://api.clerk.com/v1/users/<id>; any other URL fails the test.
type ClerkReply = { status: number; body?: unknown };
let clerk: { calls: { method: string; id: string; auth: string | null }[]; get: ClerkReply; del: ClerkReply };
beforeEach(async () => {
  clerk = {
    calls: [],
    get: {
      status: 200,
      body: {
        id: 'user_new',
        email_addresses: [
          { id: 'e1', email_address: 'other@example.test' },
          { id: 'e2', email_address: 'me@example.test' },
        ],
        primary_email_address_id: 'e2',
        first_name: 'Ada',
        last_name: 'Lovelace',
      },
    },
    del: { status: 200, body: {} },
  };
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    const m = /^https:\/\/api\.clerk\.com\/v1\/users\/([^/]+)$/.exec(url);
    if (!m) throw new Error(`unexpected outbound request: ${url}`);
    const method = init?.method ?? 'GET';
    const auth = new Headers(init?.headers).get('authorization');
    clerk.calls.push({ method, id: decodeURIComponent(m[1] as string), auth });
    const r = method === 'DELETE' ? clerk.del : clerk.get;
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status });
  });
  for (const t of ['users', 'watch', 'saved_searches', 'alert_queue', 'alerts_sent']) {
    await E.DB_USERS.prepare(`DELETE FROM ${t}`).run();
  }
  await E.DB_VULNS.prepare("DELETE FROM vulns WHERE key LIKE 'CVE-2099-%'").run();
  await E.DB_ADVISORIES.prepare("DELETE FROM advisories WHERE source_id LIKE 'GHSA-test-%'").run();
});
afterEach(() => vi.restoreAllMocks());

async function vuln(key: string, title = `Title ${key}`) {
  await E.DB_VULNS.prepare(
    `INSERT OR REPLACE INTO vulns (key, kind, title, summary, published, modified, sources, doc_key)
     VALUES (?1,'cve',?2,'s','2025-01-01','2025-01-02T00:00:00Z','["nvd"]','docs/x')`,
  )
    .bind(key, title)
    .run();
}
async function user(id: string, extra: { name?: string } = {}) {
  await E.DB_USERS.prepare('INSERT INTO users (id, email, name, created_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(id, `${id}@example.test`, extra.name ?? null, '2025-01-01T00:00:00Z')
    .run();
}
const count = async (table: string, col: string, id: string) =>
  (
    await E.DB_USERS.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${col} = ?1`)
      .bind(id)
      .first<{ n: number }>()
  )?.n;

describe('auth', () => {
  const routes: [string, string, unknown?][] = [
    ['GET', '/v1/me'],
    ['PATCH', '/v1/me', { displayName: 'x' }],
    ['DELETE', '/v1/me'],
    ['GET', '/v1/me/watch'],
    ['PUT', '/v1/me/watch/CVE-2099-0001'],
    ['DELETE', '/v1/me/watch/CVE-2099-0001'],
    ['GET', '/v1/me/saved-searches'],
    ['POST', '/v1/me/saved-searches', { name: 'a', query: 'b' }],
    ['DELETE', '/v1/me/saved-searches/6f1c1c1e-1111-4111-8111-111111111111'],
  ];
  for (const [method, path, body] of routes) {
    it(`${method} ${path} without sign-in → 401`, async () => {
      const res = await call(method, path, { body });
      expect(res.status).toBe(401);
      expect(await json(res)).toEqual({ error: 'sign_in_required' });
      expect(res.headers.get('cache-control')).toBe('private, no-store');
    });
  }
});

describe('GET /v1/me', () => {
  it('creates the row from Clerk once, with defaults', async () => {
    const res = await call('GET', '/v1/me', { user: 'user_new' });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    const me = await json(res);
    expect(me).toEqual({
      userId: 'user_new',
      email: 'me@example.test',
      displayName: 'Ada Lovelace',
      alerts: { instant: false, digest: 'daily', digestWeekday: new Date().getUTCDay() },
    });
    expect(clerk.calls).toEqual([{ method: 'GET', id: 'user_new', auth: 'Bearer sk_test_dummy' }]);
    expect(await count('users', 'id', 'user_new')).toBe(1);
    await call('GET', '/v1/me', { user: 'user_new' });
    expect(clerk.calls).toHaveLength(1);
  });
  it('Clerk 500 → 502 clerk_unavailable, no row', async () => {
    clerk.get = { status: 500 };
    const res = await call('GET', '/v1/me', { user: 'user_new' });
    expect(res.status).toBe(502);
    expect(await json(res)).toEqual({ error: 'clerk_unavailable' });
    expect(await count('users', 'id', 'user_new')).toBe(0);
  });
  it('Clerk 404 → 401', async () => {
    clerk.get = { status: 404 };
    expect((await call('GET', '/v1/me', { user: 'user_new' })).status).toBe(401);
  });
  it('displayName prefers the user-set name', async () => {
    await user('u1', { name: 'Clerk Name' });
    await E.DB_USERS.prepare("UPDATE users SET display_name = 'Mine' WHERE id = 'u1'").run();
    expect((await json(await call('GET', '/v1/me', { user: 'u1' }))).displayName).toBe('Mine');
  });
});

describe('PATCH /v1/me', () => {
  const stored = () =>
    E.DB_USERS.prepare(
      'SELECT display_name, alert_instant, digest, digest_weekday, name FROM users WHERE id = ?1',
    )
      .bind('u1')
      .first<any>();
  beforeEach(() => user('u1', { name: 'Clerk Name' }));

  it('sets and clears the display name', async () => {
    let res = await call('PATCH', '/v1/me', { user: 'u1', body: { displayName: '  Grace  ' } });
    expect(res.status).toBe(200);
    expect((await json(res)).displayName).toBe('Grace');
    expect((await stored()).display_name).toBe('Grace');
    res = await call('PATCH', '/v1/me', { user: 'u1', body: { displayName: null } });
    expect((await json(res)).displayName).toBe('Clerk Name');
    expect(await stored()).toMatchObject({ display_name: null, name: 'Clerk Name' });
  });
  it('sets each alert field on its own', async () => {
    let res = await call('PATCH', '/v1/me', { user: 'u1', body: { alerts: { instant: true } } });
    expect((await json(res)).alerts).toMatchObject({ instant: true, digest: 'daily' });
    res = await call('PATCH', '/v1/me', { user: 'u1', body: { alerts: { digest: 'weekly' } } });
    expect((await json(res)).alerts).toMatchObject({ instant: true, digest: 'weekly' });
    res = await call('PATCH', '/v1/me', { user: 'u1', body: { alerts: { digestWeekday: 4 } } });
    expect((await json(res)).alerts).toEqual({ instant: true, digest: 'weekly', digestWeekday: 4 });
    expect(await stored()).toMatchObject({ alert_instant: 1, digest: 'weekly', digest_weekday: 4 });
  });
  const bad: [string, unknown][] = [
    ['empty body', {}],
    ['empty alerts', { alerts: {} }],
    ['unknown key', { nope: 1 }],
    ['unknown alert key', { alerts: { nope: 1 } }],
    ['weekday 7', { alerts: { digestWeekday: 7 } }],
    ['fractional weekday', { alerts: { digestWeekday: 1.5 } }],
    ['bad digest', { alerts: { digest: 'hourly' } }],
    ['81-char name', { displayName: 'a'.repeat(81) }],
    ['blank name', { displayName: '   ' }],
    ['control char', { displayName: 'a\u0007b' }],
  ];
  for (const [label, body] of bad) {
    it(`rejects ${label}`, async () => {
      const res = await call('PATCH', '/v1/me', { user: 'u1', body });
      expect(res.status).toBe(400);
      expect(await json(res)).toEqual({ error: 'bad_request' });
      expect(await stored()).toMatchObject({ display_name: null, alert_instant: 0, digest: 'daily' });
    });
  }
  it('rejects non-JSON and oversized bodies', async () => {
    expect((await call('PATCH', '/v1/me', { user: 'u1', raw: 'nope' })).status).toBe(400);
    const big = JSON.stringify({ displayName: 'a', pad: 'x'.repeat(5000) });
    expect((await call('PATCH', '/v1/me', { user: 'u1', raw: big })).status).toBe(400);
  });
  it('accepts an 80-char name', async () => {
    const res = await call('PATCH', '/v1/me', { user: 'u1', body: { displayName: 'a'.repeat(80) } });
    expect(res.status).toBe(200);
  });
});

describe('watch', () => {
  beforeEach(async () => {
    await vuln('CVE-2099-0001', 'First bug');
    await vuln('CVE-2099-0002', 'Second bug');
  });

  it('PUT by CVE, then GET returns titles in camelCase', async () => {
    const res = await call('PUT', '/v1/me/watch/cve-2099-0001', { user: 'u1' });
    expect(res.status).toBe(200);
    expect(await json(res)).toMatchObject({ entryKey: 'CVE-2099-0001', title: 'First bug', alertsOn: true });
    await new Promise((r) => setTimeout(r, 5));
    await call('PUT', '/v1/me/watch/CVE-2099-0002', { user: 'u1', body: { alertsOn: false } });
    const list = await json(await call('GET', '/v1/me/watch', { user: 'u1' }));
    expect(list.limit).toBe(1000);
    expect(list.items.map((i: any) => [i.entryKey, i.title, i.alertsOn])).toEqual([
      ['CVE-2099-0002', 'Second bug', false],
      ['CVE-2099-0001', 'First bug', true],
    ]);
    expect(Object.keys(list.items[0]).sort()).toEqual(['alertsOn', 'createdAt', 'entryKey', 'title']);
  });
  it('an alias is stored as the CVE, and is one item with it', async () => {
    await E.DB_ADVISORIES.prepare(
      "INSERT OR REPLACE INTO advisories (source, source_id, vuln_key, status, published, modified, url) VALUES ('github-advisory-db','GHSA-test-aaaa-bbbb-cccc','CVE-2099-0001','active','2025-01-01','2025-01-02T00:00:00Z','https://example.test')",
    ).run();
    const a = await json(await call('PUT', '/v1/me/watch/GHSA-test-aaaa-bbbb-cccc', { user: 'u1' }));
    expect(a.entryKey).toBe('CVE-2099-0001');
    await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' });
    expect(await count('watch', 'user_id', 'u1')).toBe(1);
    // deleting by alias removes the CVE item
    expect((await call('DELETE', '/v1/me/watch/GHSA-test-aaaa-bbbb-cccc', { user: 'u1' })).status).toBe(200);
    expect(await count('watch', 'user_id', 'u1')).toBe(0);
  });
  it('unknown id 404, bad id 400, bad body 400', async () => {
    let res = await call('PUT', '/v1/me/watch/CVE-2099-9999', { user: 'u1' });
    expect([res.status, (await json(res)).error]).toEqual([404, 'not_found']);
    res = await call('PUT', '/v1/me/watch/bad%20id!', { user: 'u1' });
    expect([res.status, (await json(res)).error]).toEqual([400, 'bad_id']);
    res = await call('DELETE', '/v1/me/watch/bad%20id!', { user: 'u1' });
    expect(res.status).toBe(400);
    res = await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1', raw: 'nope' });
    expect(res.status).toBe(400);
    res = await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1', body: { alertsOn: 'yes' } });
    expect(res.status).toBe(400);
  });
  it('toggles alertsOn, keeps it when not given', async () => {
    await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' });
    let res = await json(
      await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1', body: { alertsOn: false } }),
    );
    expect(res.alertsOn).toBe(false);
    res = await json(await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' }));
    expect(res.alertsOn).toBe(false);
    res = await json(
      await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1', body: { alertsOn: true } }),
    );
    expect(res.alertsOn).toBe(true);
  });
  it('DELETE is idempotent', async () => {
    await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' });
    for (const removed of [true, false]) {
      const res = await call('DELETE', '/v1/me/watch/CVE-2099-0001', { user: 'u1' });
      expect([res.status, await json(res)]).toEqual([200, { ok: true, removed }]);
    }
    expect((await call('DELETE', '/v1/me/watch/CVE-2099-7777', { user: 'u1' })).status).toBe(200);
  });
  it('caps at 1,000 but still updates an existing item', async () => {
    const rows = Array.from({ length: 1000 }, (_, i) =>
      E.DB_USERS.prepare(
        "INSERT INTO watch (user_id, entry_key, created_at) VALUES ('u1', ?1, '2025-01-01T00:00:00Z')",
      ).bind(`CVE-2000-${String(i).padStart(4, '0')}`),
    );
    await E.DB_USERS.batch(rows);
    const res = await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' });
    expect([res.status, (await json(res)).error]).toEqual([409, 'limit_reached']);
    expect(await count('watch', 'user_id', 'u1')).toBe(1000);
    await E.DB_USERS.prepare("DELETE FROM watch WHERE entry_key = 'CVE-2000-0000'").run();
    await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' }); // now 1000 again
    const upd = await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1', body: { alertsOn: false } });
    expect(upd.status).toBe(200);
    expect((await json(upd)).alertsOn).toBe(false);
    const list = await json(await call('GET', '/v1/me/watch', { user: 'u1' }));
    expect(list.items).toHaveLength(1000);
  });
  it("one user's watch list is not another's", async () => {
    await call('PUT', '/v1/me/watch/CVE-2099-0001', { user: 'u1' });
    expect((await json(await call('GET', '/v1/me/watch', { user: 'u2' }))).items).toEqual([]);
  });
});

describe('saved searches', () => {
  const create = (body: unknown, u = 'u1') => call('POST', '/v1/me/saved-searches', { user: u, body });

  it('creates and lists newest first', async () => {
    const res = await create({
      name: '  KEV critical ',
      query: ' log4j ',
      params: { sev: ['critical'], sig: ['kev'], sort: 'new' },
      alertsOn: true,
    });
    expect(res.status).toBe(201);
    const made = await json(res);
    expect(made).toMatchObject({
      name: 'KEV critical',
      query: 'log4j',
      params: { sev: ['critical'], sig: ['kev'], sort: 'new' },
      alertsOn: true,
    });
    expect(made.id).toMatch(/^[0-9a-f-]{36}$/);
    await new Promise((r) => setTimeout(r, 5));
    await create({ name: 'second', query: '' });
    const list = await json(await call('GET', '/v1/me/saved-searches', { user: 'u1' }));
    expect(list.limit).toBe(50);
    expect(list.items.map((i: any) => i.name)).toEqual(['second', 'KEV critical']);
    expect(list.items[0]).toMatchObject({ params: {}, alertsOn: false });
    const row = await E.DB_USERS.prepare('SELECT label, params FROM saved_searches WHERE id = ?1')
      .bind(made.id)
      .first<any>();
    expect(row.label).toBe('KEV critical');
    expect(JSON.parse(row.params)).toEqual({ sig: ['kev'], sev: ['critical'], sort: 'new' });
  });
  const bad: [string, unknown][] = [
    ['type=bogus', { name: 'a', query: '', params: { type: ['bogus'] } }],
    ['sev=urgent', { name: 'a', query: '', params: { sev: ['urgent'] } }],
    ['201-char query', { name: 'a', query: 'q'.repeat(201) }],
    ['blank name', { name: ' ', query: '' }],
    ['81-char name', { name: 'n'.repeat(81), query: '' }],
    ['unknown key', { name: 'a', query: '', extra: 1 }],
    ['unknown param key', { name: 'a', query: '', params: { limit: ['5'] } }],
    ['missing query', { name: 'a' }],
  ];
  for (const [label, body] of bad) {
    it(`rejects ${label}`, async () => {
      const res = await create(body);
      expect([res.status, (await json(res)).error]).toEqual([400, 'bad_request']);
      expect(await count('saved_searches', 'user_id', 'u1')).toBe(0);
    });
  }
  it('accepts a 200-char query', async () => {
    expect((await create({ name: 'a', query: 'q'.repeat(200) })).status).toBe(201);
  });
  it('the 51st → 409', async () => {
    await E.DB_USERS.batch(
      Array.from({ length: 50 }, (_, i) =>
        E.DB_USERS.prepare(
          "INSERT INTO saved_searches (user_id, id, label, query, created_at) VALUES ('u1', ?1, 'x', '', '2025-01-01T00:00:00Z')",
        ).bind(`id-${i}`),
      ),
    );
    const res = await create({ name: 'one more', query: '' });
    expect([res.status, (await json(res)).error]).toEqual([409, 'limit_reached']);
    expect(await count('saved_searches', 'user_id', 'u1')).toBe(50);
    expect((await create({ name: 'other user', query: '' }, 'u2')).status).toBe(201);
  });
  it('deletes own; another user’s id is 404 and survives; bad id 400', async () => {
    const mine = await json(await create({ name: 'mine', query: '' }, 'u1'));
    const theirs = await json(await create({ name: 'theirs', query: '' }, 'u2'));
    let res = await call('DELETE', `/v1/me/saved-searches/${theirs.id}`, { user: 'u1' });
    expect([res.status, (await json(res)).error]).toEqual([404, 'not_found']);
    expect(await count('saved_searches', 'user_id', 'u2')).toBe(1);
    res = await call('DELETE', `/v1/me/saved-searches/${crypto.randomUUID()}`, { user: 'u1' });
    expect(res.status).toBe(404);
    res = await call('DELETE', '/v1/me/saved-searches/not-a-uuid', { user: 'u1' });
    expect(res.status).toBe(400);
    res = await call('DELETE', `/v1/me/saved-searches/${mine.id}`, { user: 'u1' });
    expect([res.status, await json(res)]).toEqual([200, { ok: true }]);
    expect(await count('saved_searches', 'user_id', 'u1')).toBe(0);
  });
});

describe('DELETE /v1/me', () => {
  const TABLES: [string, string][] = [
    ['users', 'id'],
    ['watch', 'user_id'],
    ['saved_searches', 'user_id'],
    ['alert_queue', 'user_id'],
    ['alerts_sent', 'user_id'],
  ];
  async function seed(id: string) {
    await user(id);
    await E.DB_USERS.batch([
      E.DB_USERS.prepare(
        "INSERT INTO watch (user_id, entry_key, created_at) VALUES (?1, 'CVE-2099-0001', 'x')",
      ).bind(id),
      E.DB_USERS.prepare(
        "INSERT INTO saved_searches (user_id, id, label, query, created_at) VALUES (?1, 's1', 'l', 'q', 'x')",
      ).bind(id),
      E.DB_USERS.prepare(
        "INSERT INTO alert_queue (user_id, change_id, created_at) VALUES (?1, 'c1', 'x')",
      ).bind(id),
      E.DB_USERS.prepare("INSERT INTO alerts_sent (user_id, change_id, sent_at) VALUES (?1, 'c1', 'x')").bind(
        id,
      ),
    ]);
  }
  beforeEach(async () => {
    await seed('userA');
    await seed('userB');
  });

  it('removes all of A, none of B, one Clerk DELETE', async () => {
    const res = await call('DELETE', '/v1/me', { user: 'userA' });
    expect([res.status, await json(res)]).toEqual([200, { deleted: true }]);
    expect(res.headers.get('cache-control')).toBe('private, no-store');
    for (const [t, c] of TABLES) {
      expect([t, await count(t, c, 'userA')]).toEqual([t, 0]);
      expect([t, await count(t, c, 'userB')]).toEqual([t, 1]);
    }
    expect(clerk.calls).toEqual([{ method: 'DELETE', id: 'userA', auth: 'Bearer sk_test_dummy' }]);
  });
  it('a repeat with Clerk 404 → 200', async () => {
    await call('DELETE', '/v1/me', { user: 'userA' });
    clerk.del = { status: 404 };
    const res = await call('DELETE', '/v1/me', { user: 'userA' });
    expect([res.status, await json(res)]).toEqual([200, { deleted: true }]);
    expect(clerk.calls.filter((c) => c.method === 'GET')).toEqual([]); // no loadOrCreateUser
  });
  it('Clerk 500 → 502 with rows gone; a retry succeeds', async () => {
    clerk.del = { status: 500 };
    const res = await call('DELETE', '/v1/me', { user: 'userA' });
    expect([res.status, await json(res)]).toEqual([502, { error: 'clerk_delete_failed' }]);
    for (const [t, c] of TABLES) expect([t, await count(t, c, 'userA')]).toEqual([t, 0]);
    clerk.del = { status: 200 };
    expect((await call('DELETE', '/v1/me', { user: 'userA' })).status).toBe(200);
  });
});
