import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { MCP_HEADERS, type McpIdentity, signMcpAssertion } from '@ti/core/mcp-user';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/index';
import { KNOWN_PACKAGE_SQL } from '../src/routes/watch-packages';

const SECRET = 'mcp-test-secret';
const A = 'user_2aaaaaaaaaaa';
const B = 'user_2bbbbbbbbbbb';
const CLIENT = 'https://agent.example.test/client.json';
const E = env as unknown as { DB_USERS: D1Database; DB_ADVISORIES: D1Database };

const stubClerk = async (c: any, next: () => Promise<void>) => {
  const user = c.req.header('x-test-user');
  c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
  await next();
};
const app = createApp(stubClerk as never);
const e = () => ({ ...env, MCP_HMAC_SECRET: SECRET });

async function web(method: string, path: string, user: string, body?: unknown) {
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(`https://ti-api.internal${path}`, {
      method,
      headers: { 'x-test-user': user },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    e() as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}
async function mcp(
  method: string,
  path: string,
  user: string,
  body?: unknown,
  scopes = ['mti:read', 'mti:watch'],
) {
  const id: McpIdentity = { sub: user, scopes, clientId: CLIENT };
  const text = body === undefined ? undefined : JSON.stringify(body);
  const requestId = crypto.randomUUID();
  const signed = await signMcpAssertion(
    SECRET,
    id,
    {
      requestId,
      method,
      pathWithQuery: path,
      body: text === undefined ? null : (new TextEncoder().encode(text).buffer as ArrayBuffer),
    },
    Math.floor(Date.now() / 1000),
  );
  const ctx = createExecutionContext();
  const res = await app.fetch(
    new Request(`https://ti-api.internal${path}`, {
      method,
      headers: { 'x-request-id': requestId, ...signed },
      body: text,
    }),
    e() as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}
const json = async (res: Response) => (await res.json()) as any;
const events = async (user: string) =>
  (
    await E.DB_USERS.prepare('SELECT * FROM watch_events WHERE user_id = ?1 ORDER BY at')
      .bind(user)
      .all<any>()
  ).results;
const P = '/v1/me/watch/packages';

async function seedPackages(user: string, n: number) {
  const stmts = [];
  for (let i = 0; i < n; i++)
    stmts.push(
      E.DB_USERS.prepare(
        `INSERT INTO watch_packages (user_id, ecosystem, name, created_at) VALUES (?1, 'npm', ?2, ?3)`,
      ).bind(user, `seed-${i}`, `2026-01-01T00:00:${String(i % 60).padStart(2, '0')}Z`),
    );
  await E.DB_USERS.batch(stmts);
}

/** Packages MTI has records for: only these can be watched. `Debian:12` stands for an OS release row. */
const KNOWN: [string, string][] = [
  ['PyPI', 'langchain'],
  ['npm', 'left-pad'],
  ['npm', 'lodash'],
  ['npm', 'x'],
  ['npm', 'mine'],
  ['npm', 'site'],
  ['npm', 'b-pkg'],
  ['npm', 'race-1'],
  ['npm', 'race-2'],
  ['npm', 'one-more'],
  ['npm', '@types/node'],
  ['Maven', 'org.apache.logging.log4j:log4j-core'],
  ['Debian:12', 'openssl'],
  ...Array.from({ length: 200 }, (_, i): [string, string] => ['npm', `seed-${i}`]),
];

beforeEach(async () => {
  await E.DB_ADVISORIES.exec('DELETE FROM affected');
  await E.DB_ADVISORIES.batch(
    KNOWN.map(([eco, name], i) =>
      E.DB_ADVISORIES.prepare(
        "INSERT INTO affected (ecosystem, name, source, source_id, range_no, vuln_key, range_type) VALUES (?1, ?2, 'osv', ?3, 0, ?3, 'SEMVER')",
      ).bind(eco, name, `T-${i}`),
    ),
  );
  for (const t of ['watch_packages', 'watch_events', 'watch', 'users'])
    await E.DB_USERS.exec(`DELETE FROM ${t}`);
  await E.DB_USERS.exec('DELETE FROM mcp_blocks');
});

describe('package watches', () => {
  it('adds, re-adds idempotently, lists newest first, removes', async () => {
    let r = await web('PUT', `${P}/pypi/LangChain`, A);
    expect([r.status, await json(r)]).toEqual([200, { created: true }]);
    r = await web('PUT', `${P}/PyPI/langchain`, A, {});
    expect(await json(r)).toEqual({ created: false });
    await web('PUT', `${P}/npm/left-pad`, A);
    r = await web('GET', P, A);
    const list = await json(r);
    expect(list.limit).toBe(200);
    expect(list.items.map((i: any) => `${i.ecosystem}/${i.name}`).sort()).toEqual([
      'PyPI/langchain',
      'npm/left-pad',
    ]);
    expect(list.items[0]).toMatchObject({ alertsOn: true });
    r = await web('PUT', `${P}/PyPI/langchain`, A, { alertsOn: false });
    expect(await json(r)).toEqual({ created: false });
    expect((await json(await web('GET', P, A))).items.find((i: any) => i.name === 'langchain').alertsOn).toBe(
      false,
    );
    r = await web('DELETE', `${P}/PyPI/langchain`, A);
    expect(await json(r)).toEqual({ removed: true });
    expect(await json(await web('DELETE', `${P}/PyPI/langchain`, A))).toEqual({ removed: false });
  });

  it('only a package MTI has records for can be watched (404 unknown_package); an OS name matches its releases', async () => {
    const r = await web('PUT', `${P}/npm/not-in-mti`, A);
    expect([r.status, (await json(r)).error]).toEqual([404, 'unknown_package']);
    expect((await json(await web('GET', P, A))).items).toEqual([]);
    expect((await web('PUT', `${P}/Debian/openssl`, A)).status).toBe(200);
    expect((await web('PUT', `${P}/Debian/curl`, A)).status).toBe(404);
  });

  it('the known-package check is two exact seeks on affected_by_name, never a scan or a name-only seek', async () => {
    const plan = (
      await E.DB_ADVISORIES.prepare(`EXPLAIN QUERY PLAN ${KNOWN_PACKAGE_SQL}`).bind('npm', 'openssl').all<{
        detail: string;
      }>()
    ).results.map((r) => r.detail);
    const text = plan.join(' | ');
    expect(text).toContain('affected_by_name (name=? AND ecosystem=?)');
    expect(text).toContain('affected_by_name (name=? AND ecosystem>? AND ecosystem<?)');
    expect(text).not.toMatch(/SCAN (?!CONSTANT)/);
    expect(text).not.toContain('sqlite_autoindex_affected');
    expect(text.replace(/\(name=\? AND ecosystem[^)]*\)/g, '')).not.toMatch(/\(name=\?\)/);
  });

  it('a package name common in other ecosystems is answered without reading those rows', async () => {
    await E.DB_ADVISORIES.batch(
      Array.from({ length: 60 }, (_, i) =>
        E.DB_ADVISORIES.prepare(
          "INSERT INTO affected (ecosystem, name, source, source_id, range_no, vuln_key, range_type) VALUES (?1, 'linux', 'osv', ?2, 0, ?2, 'ECOSYSTEM')",
        ).bind(i % 2 ? `Debian:${i}` : `Ubuntu:${i}`, `L-${i}`),
      ),
    );
    const res = await E.DB_ADVISORIES.prepare(KNOWN_PACKAGE_SQL).bind('npm', 'linux').run();
    expect((res.results[0] as { x: number }).x).toBe(0);
    // rows_read counts what D1 touched: two index seeks that find nothing read no `linux` row.
    expect(res.meta.rows_read ?? 0).toBeLessThan(5);
    const r = await web('PUT', `${P}/npm/linux`, A);
    expect([r.status, (await json(r)).error]).toEqual([404, 'unknown_package']);
    expect((await web('PUT', `${P}/Debian/linux`, A)).status).toBe(200);
  });

  it('refuses a bad ecosystem or name with 400 invalid_argument', async () => {
    for (const path of [
      `${P}/nope/x`,
      `${P}/npm/${'a'.repeat(215)}`,
      `${P}/npm/a%20b`,
      `${P}/Maven/nocolon`,
      `${P}/npm/%40scope`,
    ]) {
      const r = await web('PUT', path, A);
      expect([path, r.status, (await json(r)).error]).toEqual([path, 400, 'invalid_argument']);
    }
  });

  it('round-trips scoped npm and Maven names encoded in one segment, decoded once', async () => {
    expect((await web('PUT', `${P}/npm/%40types%2Fnode`, A)).status).toBe(200);
    expect((await web('PUT', `${P}/Maven/org.apache.logging.log4j%3Alog4j-core`, A)).status).toBe(200);
    const names = (await json(await web('GET', P, A))).items.map((i: any) => i.name).sort();
    expect(names).toEqual(['@types/node', 'org.apache.logging.log4j:log4j-core']);
    // %2540 is the literal text "%40": decoded once, it is not a valid scope.
    expect((await web('PUT', `${P}/npm/%252540types%2Fnode`, A)).status).toBe(400);
    expect(await json(await web('DELETE', `${P}/npm/%40types%2Fnode`, A))).toEqual({ removed: true });
  });

  it('keeps users apart', async () => {
    await web('PUT', `${P}/npm/mine`, A);
    expect((await json(await web('GET', P, B))).items).toEqual([]);
    expect(await json(await web('DELETE', `${P}/npm/mine`, B))).toEqual({ removed: false });
    expect((await json(await web('GET', P, A))).items).toHaveLength(1);
  });

  it('caps at 200: 199 → 200 → 409, and two adds at once at 199 make one', async () => {
    await seedPackages(A, 199);
    const [x, y] = await Promise.all([web('PUT', `${P}/npm/race-1`, A), web('PUT', `${P}/npm/race-2`, A)]);
    expect([x.status, y.status].sort()).toEqual([200, 409]);
    expect(await json(x.status === 200 ? x : y)).toEqual({ created: true });
    const count = await E.DB_USERS.prepare('SELECT COUNT(*) AS n FROM watch_packages WHERE user_id = ?1')
      .bind(A)
      .first<{ n: number }>();
    expect(count?.n).toBe(200);
    const over = await web('PUT', `${P}/npm/one-more`, A);
    expect([over.status, await json(over)]).toEqual([409, { error: 'limit_reached' }]);
    // an existing watch can still be re-added at the cap
    expect(await json(await web('PUT', `${P}/npm/seed-0`, A))).toEqual({ created: false });
  });
});

describe('watch_events', () => {
  it('MCP callers write events in the same change, the website does not', async () => {
    await web('PUT', `${P}/npm/site`, A);
    expect(await events(A)).toEqual([]);
    await mcp('PUT', `${P}/npm/lodash`, A, {});
    await mcp('PUT', `${P}/npm/lodash`, A, {}); // no change, no event
    await mcp('PUT', '/v1/me/watch/CVE-2099-0001', A, {}); // unknown entry: no event
    await mcp('DELETE', `${P}/npm/lodash`, A);
    await mcp('DELETE', `${P}/npm/lodash`, A); // no-op: no event
    const ev = await events(A);
    expect(ev.map((x) => [x.action, x.target, x.via, x.client_host, x.notified_at])).toEqual([
      ['add', 'pkg:npm/lodash', 'mcp', 'agent.example.test', null],
      ['remove', 'pkg:npm/lodash', 'mcp', 'agent.example.test', null],
    ]);
  });

  it('an MCP caller may not turn alerts off, but can turn them on', async () => {
    await web('PUT', `${P}/npm/x`, A, { alertsOn: false });
    const off = await mcp('PUT', `${P}/npm/x`, A, { alertsOn: false });
    expect([off.status, (await json(off)).error]).toEqual([403, 'not_allowed_for_mcp']);
    expect((await mcp('PUT', `${P}/npm/x`, A, { alertsOn: true })).status).toBe(200);
    expect((await events(A)).map((x) => x.action)).toEqual(['alerts_on']);
  });

  it('needs mti:watch to write', async () => {
    const r = await mcp('PUT', `${P}/npm/x`, A, {}, ['mti:read']);
    expect(r.status).toBe(403);
    expect((await mcp('GET', P, A, undefined, ['mti:read'])).status).toBe(200);
  });

  it('entry watch routes write events for MCP only, answer created / removed, and share the removal cap', async () => {
    const vuln = (await import('cloudflare:workers')).env as any;
    await vuln.DB_VULNS.prepare(
      "INSERT OR REPLACE INTO vulns (key, kind, title, modified) VALUES ('CVE-2099-0001', 'cve', 't', 'x')",
    ).run();
    expect((await json(await web('PUT', '/v1/me/watch/CVE-2099-0001', A))).created).toBe(true);
    expect(await events(A)).toEqual([]);
    expect(await json(await web('DELETE', '/v1/me/watch/CVE-2099-0001', A))).toEqual({
      ok: true,
      removed: true,
    });
    expect((await json(await mcp('PUT', '/v1/me/watch/cve-2099-0001', A, {}))).created).toBe(true);
    expect((await json(await mcp('PUT', '/v1/me/watch/CVE-2099-0001', A, {}))).created).toBe(false);
    const off = await mcp('PUT', '/v1/me/watch/CVE-2099-0001', A, { alertsOn: false });
    expect(off.status).toBe(403);
    // 19 package removals plus this entry removal reach the cap of 20
    await seedPackages(A, 20);
    for (let i = 0; i < 19; i++) await mcp('DELETE', `${P}/npm/seed-${i}`, A);
    expect(await json(await mcp('DELETE', '/v1/me/watch/CVE-2099-0001', A))).toEqual({
      ok: true,
      removed: true,
    });
    const over = await mcp('DELETE', `${P}/npm/seed-19`, A);
    expect([over.status, (await json(over)).error]).toEqual([429, 'removal_limit']);
    expect(
      (await events(A)).filter((x) => x.target.startsWith('entry:')).map((x) => [x.action, x.target]),
    ).toEqual([
      ['add', 'entry:CVE-2099-0001'],
      ['remove', 'entry:CVE-2099-0001'],
    ]);
  });
});

describe('the 20-removal cap (MCP only)', () => {
  it('allows 20 removals in a day, refuses the 21st with 429 and Retry-After', async () => {
    await seedPackages(A, 25);
    for (let i = 0; i < 20; i++) {
      const r = await mcp('DELETE', `${P}/npm/seed-${i}`, A);
      expect([i, r.status, (await json(r)).removed]).toEqual([i, 200, true]);
    }
    const r = await mcp('DELETE', `${P}/npm/seed-20`, A);
    expect([r.status, (await json(r)).error]).toEqual([429, 'removal_limit']);
    expect(Number(r.headers.get('retry-after'))).toBeGreaterThan(0);
    // nothing to remove is not limited; the website is not capped
    expect((await mcp('DELETE', `${P}/npm/nothing-here`, A)).status).toBe(200);
    expect((await json(await web('DELETE', `${P}/npm/seed-20`, A))).removed).toBe(true);
    // another user is unaffected
    await web('PUT', `${P}/npm/b-pkg`, B);
    expect((await json(await mcp('DELETE', `${P}/npm/b-pkg`, B))).removed).toBe(true);
  });
});

describe('PATCH /v1/me from MCP', () => {
  const seedUser = (digest: string) =>
    E.DB_USERS.prepare(
      "INSERT OR REPLACE INTO users (id, email, created_at, digest, alert_instant) VALUES (?1, 'a@example.test', 'x', ?2, 0)",
    )
      .bind(A, digest)
      .run();
  it('turns a digest on while it is off, and records an event', async () => {
    await seedUser('off');
    const r = await mcp('PATCH', '/v1/me', A, { alerts: { digest: 'weekly' } });
    expect(r.status).toBe(200);
    expect((await json(r)).alerts.digest).toBe('weekly');
    expect((await events(A)).map((x) => [x.action, x.target])).toEqual([['digest_on', 'settings']]);
    // now it is on: any further MCP change is refused
    const again = await mcp('PATCH', '/v1/me', A, { alerts: { digest: 'daily' } });
    expect([again.status, (await json(again)).error]).toEqual([403, 'not_allowed_for_mcp']);
  });
  it('refuses every other body with 403 not_allowed_for_mcp', async () => {
    await seedUser('off');
    for (const body of [
      { displayName: 'x' },
      { alerts: { instant: true } },
      { alerts: { digest: 'off' } },
      { alerts: { digest: 'daily', instant: true } },
      { alerts: { digest: 'daily' }, email: 'evil@example.test' },
      { email: 'evil@example.test' },
      {},
    ]) {
      const r = await mcp('PATCH', '/v1/me', A, body);
      expect([JSON.stringify(body), r.status]).toEqual([JSON.stringify(body), 403]);
    }
    expect(await events(A)).toEqual([]);
  });
  it('keeps the full body for the website', async () => {
    await seedUser('off');
    const r = await web('PATCH', '/v1/me', A, {
      displayName: 'Ada',
      alerts: { instant: true, digest: 'off' },
    });
    expect(r.status).toBe(200);
    expect(await events(A)).toEqual([]);
  });
});
