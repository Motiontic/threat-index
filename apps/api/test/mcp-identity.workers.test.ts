import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { MCP_HEADERS, type McpIdentity, signMcpAssertion } from '@ti/core/mcp-user';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/index';
import { deleteUserData } from '../src/lib/delete-user';
import { findMcpRoute } from '../src/lib/mcp-routes';

const SECRET = 'mcp-test-secret';
const NEXT = 'mcp-test-secret-next';
const SUB = 'user_2abcdefghijk';
const ADMIN = 'user_2adminadmin1';
const CLIENT = 'client-abc';
const READ: McpIdentity = { sub: SUB, scopes: ['mti:read'], clientId: CLIENT };
const BOTH: McpIdentity = { sub: SUB, scopes: ['mti:read', 'mti:watch'], clientId: CLIENT };

const E = env as unknown as { DB_USERS: D1Database };

// Records the keys the per-user limit sees.
let limitKeys: string[] = [];
const recorder = { limit: async ({ key }: { key: string }) => (limitKeys.push(key), { success: true }) };

/** A stand-in for the Clerk middleware: a session user from a header, with an optional token type. */
let clerkRan = 0;
const stubClerk = async (c: any, next: () => Promise<void>) => {
  clerkRan++;
  const user = c.req.header('x-test-user');
  const tokenType = c.req.header('x-test-token-type');
  c.set(
    'clerkAuth' as never,
    (() => (user ? { userId: user, ...(tokenType ? { tokenType } : {}) } : { userId: null })) as never,
  );
  await next();
};
const app = createApp(stubClerk as never);

const baseEnv = () => ({
  ...env,
  MCP_HMAC_SECRET: SECRET,
  MCP_HMAC_SECRET_NEXT: NEXT,
  ADMIN_USER_IDS: `${SUB},${ADMIN}`,
  RL_USER: recorder,
  RL_PUBLIC: recorder,
});

async function fetchApp(req: Request, e: object = baseEnv()) {
  const ctx = createExecutionContext();
  const res = await app.fetch(req, e as never, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

interface SignedOpts {
  id?: McpIdentity;
  secret?: string;
  ts?: number;
  /** The body the assertion covers, when different from the one sent. */
  signedBody?: string;
  signedPath?: string;
  extra?: Record<string, string>;
  body?: string;
  requestId?: string;
}
async function mcp(method: string, path: string, o: SignedOpts = {}, e?: object) {
  const requestId = o.requestId ?? crypto.randomUUID();
  const enc = (s: string | undefined) =>
    s === undefined ? null : (new TextEncoder().encode(s).buffer as ArrayBuffer);
  const signed = await signMcpAssertion(
    o.secret ?? SECRET,
    o.id ?? READ,
    { requestId, method, pathWithQuery: o.signedPath ?? path, body: enc(o.signedBody ?? o.body) },
    o.ts ?? Math.floor(Date.now() / 1000),
  );
  const init: RequestInit = { method, headers: { 'x-request-id': requestId, ...signed, ...o.extra } };
  if (o.body !== undefined) init.body = o.body;
  return fetchApp(new Request(`https://ti-api.internal${path}`, init), e);
}
const json = async (res: Response) => (await res.json()) as any;

beforeEach(async () => {
  limitKeys = [];
  clerkRan = 0;
  await E.DB_USERS.exec('DELETE FROM mcp_blocks');
});

describe('a signed MCP call', () => {
  it('succeeds as that user on an allowed route, is limited on u:<sub>, and never reaches Clerk', async () => {
    const res = await mcp('GET', '/v1/me/watch');
    expect(res.status).toBe(200);
    expect(await json(res)).toMatchObject({ items: [] });
    expect(limitKeys).toEqual([`u:${SUB}`]);
    expect(clerkRan).toBe(0);
  });
  it('is rate limited on the user key when the limit is hit', async () => {
    const deny = { limit: async () => ({ success: false }) };
    const res = await mcp('GET', '/v1/me/watch', {}, { ...baseEnv(), RL_USER: deny });
    expect(res.status).toBe(429);
  });
  it('accepts a signature made with the next secret', async () => {
    expect((await mcp('GET', '/v1/me/watch', { secret: NEXT })).status).toBe(200);
  });
  it('signs and checks the query string', async () => {
    expect((await mcp('GET', '/v1/search?q=log4j')).status).toBe(200);
    const res = await mcp('GET', '/v1/search?q=log4j', { signedPath: '/v1/search?q=other' });
    expect(res.status).toBe(401);
  });
});

describe('a signed MCP call on cachedPublic routes', () => {
  it('returns 200, bypasses the public cache and gets the full-record view', async () => {
    const V = env as unknown as { DB_VULNS: D1Database };
    await V.DB_VULNS.prepare(
      `INSERT OR REPLACE INTO vulns (key, kind, title, summary, published, modified, cvss, cvss_version, cvss_source, cwe, kev_added, ransomware, epss, sources, doc_key)
       VALUES ('CVE-2031-0001','cve','T','S','2025-01-01','2025-01-02T00:00:00Z',7.5,'3.1','nvd','["CWE-79"]',NULL,0,0.5,'["nvd"]','docs/x')`,
    ).run();
    for (const path of ['/v1/home', '/v1/search?q=log4j', '/v1/entries/CVE-2031-0001']) {
      const res = await mcp('GET', path);
      expect(res.status, path).toBe(200);
      // Search sets its own header and has no per-user view; the cachedPublic routes must skip the cache.
      if (!path.startsWith('/v1/search'))
        expect(res.headers.get('cache-control'), path).toBe('private, no-store');
      if (path.startsWith('/v1/entries/')) expect((await json(res)).access).toBe('full');
    }
    expect(clerkRan).toBe(0);
  });
});

describe('route allow-list and scopes', () => {
  it('refuses admin, internal and destructive routes with 403 not_allowed_for_mcp, even for an admin user', async () => {
    const admin: McpIdentity = { sub: SUB, scopes: ['mti:read', 'mti:watch'], clientId: CLIENT };
    for (const [method, path] of [
      ['GET', '/v1/admin/ops'],
      ['POST', '/internal/jobs/x'],
      ['GET', '/internal/jobs/x'],
      ['DELETE', '/v1/me'],
      ['GET', '/v1/me/saved-searches'],
      ['POST', '/webhooks/clerk'],
      ['PATCH', '/v1/me'],
      ['HEAD', '/v1/search'],
    ] as const) {
      const res = await mcp(method, path, { id: admin });
      expect(res.status, `${method} ${path}`).toBe(403);
      if (method !== 'HEAD')
        expect(await json(res), `${method} ${path}`).toEqual({ error: 'not_allowed_for_mcp' });
    }
  });
  it('refuses look-alike paths: trailing slash, encoded segments, case', async () => {
    for (const path of ['/v1/me/', '/v1/%6De', '/v1/Me', '/v1//me', '/v1/search/']) {
      expect((await mcp('GET', path)).status, path).toBe(403);
    }
  });
  it('never gives an MCP identity admin rights, even if the user is listed in ADMIN_USER_IDS', async () => {
    const res = await mcp('GET', '/v1/admin/ops', { id: BOTH });
    expect(res.status).toBe(403);
    expect((await json(res)).error).toBe('not_allowed_for_mcp');
  });
  it('mti:read alone cannot write a watch: 403 insufficient_scope', async () => {
    const res = await mcp('PUT', '/v1/me/watch/CVE-2025-1', { body: '{}' });
    expect(res.status).toBe(403);
    expect(await json(res)).toEqual({ error: 'insufficient_scope', scope: 'mti:watch' });
    const del = await mcp('DELETE', '/v1/me/watch/packages/npm/lodash');
    expect(del.status).toBe(403);
    expect((await json(del)).scope).toBe('mti:watch');
  });
  it('mti:watch passes the scope check on a watch write', async () => {
    const res = await mcp('PUT', '/v1/me/watch/packages/npm/lodash', { id: BOTH, body: '{}' });
    expect(res.status).toBe(501); // stub, after auth
  });
  it('every route has its scope in the table', () => {
    expect(findMcpRoute('GET', '/v1/entries/CVE-2025-1')?.scope).toBe('mti:read');
    expect(findMcpRoute('POST', '/v1/packages/check')?.scope).toBe('mti:read');
    expect(findMcpRoute('DELETE', '/v1/deep-query/abc')?.scope).toBe('mti:read');
    expect(findMcpRoute('GET', '/v1/incidents/s/i')?.scope).toBe('mti:read');
    expect(findMcpRoute('PUT', '/v1/me/watch/x')?.scope).toBe('mti:watch');
    expect(findMcpRoute('DELETE', '/v1/me/watch/packages/npm/a')?.scope).toBe('mti:watch');
    expect(findMcpRoute('GET', '/v1/me/watch/packages')?.scope).toBe('mti:read');
    expect(findMcpRoute('DELETE', '/v1/me')).toBeNull();
    expect(findMcpRoute('GET', '/v1/admin/ops')).toBeNull();
  });
});

describe('bad assertions', () => {
  it('a changed body gets 401', async () => {
    const res = await mcp('POST', '/v1/packages/check', { body: '{"a":2}', signedBody: '{"a":1}' });
    expect(res.status).toBe(401);
    expect(await json(res)).toEqual({ error: 'bad_mcp_assertion' });
  });
  it('an old or future timestamp gets 401', async () => {
    const now = Math.floor(Date.now() / 1000);
    expect((await mcp('GET', '/v1/me/watch', { ts: now - 120 })).status).toBe(401);
    expect((await mcp('GET', '/v1/me/watch', { ts: now + 120 })).status).toBe(401);
  });
  it('a wrong secret gets 401, and so does an API with no secret set', async () => {
    expect((await mcp('GET', '/v1/me/watch', { secret: 'wrong' })).status).toBe(401);
    const none = { ...baseEnv(), MCP_HMAC_SECRET: undefined, MCP_HMAC_SECRET_NEXT: undefined };
    expect((await mcp('GET', '/v1/me/watch', {}, none)).status).toBe(401);
  });
  it('a missing header, an unknown x-ti-mcp header or a request id mismatch gets 401, never Clerk', async () => {
    const id = crypto.randomUUID();
    const signed = await signMcpAssertion(
      SECRET,
      READ,
      { requestId: id, method: 'GET', pathWithQuery: '/v1/me/watch', body: null },
      Math.floor(Date.now() / 1000),
    );
    const { [MCP_HEADERS.sig]: _drop, ...noSig } = signed;
    const missing = await fetchApp(
      new Request('https://ti-api.internal/v1/me/watch', {
        headers: { 'x-request-id': id, ...noSig, 'x-test-user': SUB },
      }),
    );
    expect(missing.status).toBe(401);
    const unknown = await mcp('GET', '/v1/me/watch', { extra: { 'x-ti-mcp-admin': '1' } });
    expect(unknown.status).toBe(401);
    const mismatch = await fetchApp(
      new Request('https://ti-api.internal/v1/me/watch', {
        headers: { 'x-request-id': crypto.randomUUID(), ...signed },
      }),
    );
    expect(mismatch.status).toBe(401);
    expect(clerkRan).toBe(0);
  });
  it('a body over the limit gets 401', async () => {
    const big = 'x'.repeat(2 * 1024 * 1024 + 1);
    expect((await mcp('POST', '/v1/packages/check', { body: big })).status).toBe(401);
  });
  it('an MCP header with a cookie or an Authorization header gets 400', async () => {
    for (const extra of [{ cookie: '__session=abc' }, { authorization: 'Bearer abc' }] as Record<
      string,
      string
    >[]) {
      const res = await mcp('GET', '/v1/me/watch', { extra });
      expect(res.status).toBe(400);
      expect(await json(res)).toEqual({ error: 'ambiguous_auth' });
    }
  });
});

describe('block list', () => {
  const block = (kind: string, id: string, expires: string | null) =>
    E.DB_USERS.prepare(
      `INSERT INTO mcp_blocks (kind, id, reason, created_at, expires_at) VALUES (?1, ?2, 'abuse', '2026-01-01T00:00:00Z', ?3)`,
    )
      .bind(kind, id, expires)
      .run();

  it('refuses a blocked user at once, with a valid assertion', async () => {
    await block('user', SUB, null);
    const res = await mcp('GET', '/v1/me/watch');
    expect(res.status).toBe(403);
    expect(await json(res)).toEqual({ error: 'blocked' });
  });
  it('refuses a blocked client', async () => {
    await block('client', CLIENT, '2999-01-01T00:00:00Z');
    expect((await mcp('GET', '/v1/me/watch')).status).toBe(403);
  });
  it('ignores an expired block and a block of the other kind', async () => {
    await block('user', SUB, '2020-01-01T00:00:00Z');
    await block('client', SUB, null); // a client id equal to the user id does not block the user
    await block('user', CLIENT, null);
    expect((await mcp('GET', '/v1/me/watch')).status).toBe(200);
  });
  it('does not touch session traffic', async () => {
    await block('user', SUB, null);
    const res = await fetchApp(
      new Request('https://ti-api.internal/v1/me/watch', { headers: { 'x-test-user': SUB } }),
    );
    expect(res.status).toBe(200);
  });
});

describe('stubs', () => {
  it('answer 501 for a signed-in caller and 401 for an anonymous one', async () => {
    const stubs: [string, string][] = [
      ['POST', '/v1/packages/check'],
      ['GET', '/v1/me/watch/packages'],
      ['PUT', '/v1/me/watch/packages/npm/lodash'],
      ['DELETE', '/v1/me/watch/packages/npm/lodash'],
      ['GET', '/v1/me/changes'],
      ['DELETE', '/v1/deep-query/abc'],
    ];
    for (const [method, path] of stubs) {
      const anon = await fetchApp(new Request(`https://ti-api.internal${path}`, { method }));
      expect(anon.status, `anon ${method} ${path}`).toBe(401);
      const user = await fetchApp(
        new Request(`https://ti-api.internal${path}`, { method, headers: { 'x-test-user': SUB } }),
      );
      expect(user.status, `user ${method} ${path}`).toBe(501);
      expect(await json(user)).toEqual({ error: 'not_implemented' });
    }
  });
});

describe('session behaviour is unchanged', () => {
  it('a session user is limited on u:<id>; no user falls back to the IP key', async () => {
    await fetchApp(new Request('https://ti-api.internal/v1/me/watch', { headers: { 'x-test-user': SUB } }));
    expect(limitKeys).toEqual([`u:${SUB}`]);
    limitKeys = [];
    await fetchApp(
      new Request('https://ti-api.internal/v1/sources', { headers: { 'cf-connecting-ip': '203.0.113.9' } }),
    );
    expect(limitKeys).toEqual(['ip:203.0.113.9']);
  });
  it('an OAuth access token sent straight to the API never counts as signed in', async () => {
    const res = await fetchApp(
      new Request('https://ti-api.internal/v1/me/watch', {
        headers: { 'x-test-user': SUB, 'x-test-token-type': 'oauth_token' },
      }),
    );
    expect(res.status).toBe(401);
    const ok = await fetchApp(
      new Request('https://ti-api.internal/v1/me/watch', {
        headers: { 'x-test-user': SUB, 'x-test-token-type': 'session_token' },
      }),
    );
    expect(ok.status).toBe(200);
  });
  it('a request with no MCP header passes mcpIdentity untouched, whatever else it carries', async () => {
    const res = await fetchApp(
      new Request('https://ti-api.internal/v1/me/watch', {
        headers: { 'x-test-user': SUB, cookie: '__session=abc', authorization: 'Bearer abc' },
      }),
    );
    expect(res.status).toBe(200);
  });
});

describe('deleteUserData', () => {
  const NOW = new Date('2026-11-26T10:00:00.000Z');
  it('removes the new rows and leaves a 30-day block', async () => {
    const db = E.DB_USERS;
    await db.batch([
      db.prepare(
        `INSERT INTO users (id, email, created_at) VALUES ('user_del', 'a@example.test', '2026-01-01')`,
      ),
      db.prepare(
        `INSERT INTO watch (user_id, entry_key, created_at) VALUES ('user_del', 'CVE-1', '2026-01-01')`,
      ),
      db.prepare(
        `INSERT INTO watch_packages (user_id, ecosystem, name, created_at) VALUES ('user_del', 'npm', 'a', '2026-01-01')`,
      ),
      db.prepare(
        `INSERT INTO package_usage (user_id, day, packages, calls) VALUES ('user_del', '2026-11-25', 5, 1)`,
      ),
      db.prepare(
        `INSERT INTO watch_packages (user_id, ecosystem, name, created_at) VALUES ('user_keep', 'npm', 'a', '2026-01-01')`,
      ),
    ]);
    await deleteUserData(db, 'user_del', NOW);
    for (const t of [
      'users WHERE id',
      'watch WHERE user_id',
      'watch_packages WHERE user_id',
      'package_usage WHERE user_id',
    ]) {
      const row = await db.prepare(`SELECT count(*) AS n FROM ${t} = 'user_del'`).first<{ n: number }>();
      expect(row?.n, t).toBe(0);
    }
    const kept = await db
      .prepare(`SELECT count(*) AS n FROM watch_packages WHERE user_id = 'user_keep'`)
      .first<{ n: number }>();
    expect(kept?.n).toBe(1);
    const block = await db.prepare(`SELECT * FROM mcp_blocks WHERE id = 'user_del'`).first<any>();
    expect(block).toEqual({
      kind: 'user',
      id: 'user_del',
      reason: 'deleted',
      created_at: '2026-11-26T10:00:00.000Z',
      expires_at: '2026-12-26T10:00:00.000Z',
    });
  });
  it('blocks a deleted user on MCP, and never shortens an existing block', async () => {
    const db = E.DB_USERS;
    await db
      .prepare(
        `INSERT INTO mcp_blocks (kind, id, reason, created_at, expires_at) VALUES ('user', 'user_perm', 'abuse', '2026-01-01', NULL)`,
      )
      .run();
    await deleteUserData(db, 'user_perm', NOW);
    const row = await db
      .prepare(`SELECT reason, expires_at FROM mcp_blocks WHERE id = 'user_perm'`)
      .first<any>();
    expect(row).toEqual({ reason: 'abuse', expires_at: null });
    await deleteUserData(db, 'user_twice00000', NOW);
    await deleteUserData(db, 'user_twice00000', new Date('2026-11-20T00:00:00.000Z'));
    const twice = await db
      .prepare(`SELECT expires_at FROM mcp_blocks WHERE id = 'user_twice00000'`)
      .first<any>();
    expect(twice.expires_at).toBe('2026-12-26T10:00:00.000Z');
  });
  it('a deleted user is refused on MCP at once; another user is not', async () => {
    await deleteUserData(E.DB_USERS, 'user_gone000000');
    const gone = await mcp('GET', '/v1/me/watch', { id: { ...READ, sub: 'user_gone000000' } });
    expect(gone.status).toBe(403);
    expect(await json(gone)).toEqual({ error: 'blocked' });
    expect((await mcp('GET', '/v1/me/watch')).status).toBe(200);
  });
});
