import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { MCP_HEADERS, type McpIdentity, signMcpAssertion } from '@ti/core/mcp-user';
import { type Comparer, inRange, comparerFor as realComparerFor } from '@ti/core/versions';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/index';
import { NOTES } from '../src/lib/packages-answer';
import { AFFECTED_SQL, SIGNALS_SQL, VULNS_SQL } from '../src/lib/packages-lookup';
import { NOTE } from '../src/lib/packages-match';
import { createPackagesRoute, type PackagesDeps } from '../src/routes/packages';

const { Hono } = await import('hono');

const E = env as unknown as {
  DB_USERS: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_SIGNALS: D1Database;
  SETTINGS: KVNamespace;
};

const NOW = new Date('2026-11-26T12:00:00Z');
const DAY = '2026-11-26';
const toy: Comparer = { valid: (v) => /^\d+$/.test(v), compare: (a, b) => Number(a) - Number(b) };
const toyRules = { inRange, comparerFor: () => toy } as PackagesDeps['versions'];

function makeApp(deps: PackagesDeps = { now: () => NOW }) {
  const app = new Hono();
  app.use('/v1/*', async (c, next) => {
    const user = c.req.header('x-test-user');
    c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
    await next();
  });
  app.route('/', createPackagesRoute(deps) as never);
  return app;
}
let app = makeApp();

async function call(
  body: unknown,
  o: { user?: string | null; e?: object; raw?: string; deps?: PackagesDeps } = {},
) {
  const user = o.user === undefined ? 'user_a' : o.user;
  const headers: Record<string, string> = {};
  if (user) headers['x-test-user'] = user;
  const init: RequestInit = { method: 'POST', headers };
  init.body = o.raw !== undefined ? o.raw : JSON.stringify(body);
  const ctx = createExecutionContext();
  const a = o.deps ? makeApp(o.deps) : app;
  const res = await a.fetch(
    new Request('https://api.test/v1/packages/check', init),
    (o.e ?? env) as never,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}
const json = async (res: Response) => (await res.json()) as any;
const pk = (name: string, version = '1.0.0', ecosystem = 'npm') => ({ ecosystem, name, version });
const checkOne = async (p: unknown, o: Parameters<typeof call>[1] = {}) => {
  const res = await call({ packages: [p] }, o);
  expect(res.status).toBe(200);
  return json(res);
};

// --- seeding ------------------------------------------------------------------------------------

interface Range {
  type?: 'SEMVER' | 'ECOSYSTEM' | 'EXACT';
  introduced?: string;
  fixed?: string | null;
  last?: string | null;
  versions?: string[];
}
interface Rec {
  id: string;
  name: string;
  key?: string;
  source?: string;
  ecosystem?: string;
  ranges?: Range[];
  reviewed?: number;
  severity?: string | null;
  summary?: string | null;
  url?: string | null;
  status?: string;
  modified?: string;
}
const exact = (...versions: string[]): Range => ({ type: 'EXACT', versions });
const allVersions: Range = { type: 'SEMVER', introduced: '0' };

function recordStatements(r: Rec) {
  const key = r.key ?? r.id;
  const source = r.source ?? 'github-advisory-db';
  const stmts = [
    E.DB_ADVISORIES.prepare(
      `INSERT INTO package_advisories (source, source_id, vuln_key, status, summary, severity, reviewed, url, published, modified)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)`,
    ).bind(
      source,
      r.id,
      key,
      r.status ?? 'active',
      r.summary ?? null,
      r.severity ?? null,
      r.reviewed ?? 1,
      r.url ?? null,
      r.modified ?? '2026-02-03T00:00:00Z',
    ),
  ];
  for (const [i, g] of (r.ranges ?? [exact('1.0.0')]).entries()) {
    stmts.push(
      E.DB_ADVISORIES.prepare(
        `INSERT INTO affected (ecosystem, name, source, source_id, range_no, vuln_key, range_type, introduced, fixed, last_affected, versions)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
      ).bind(
        r.ecosystem ?? 'npm',
        r.name,
        source,
        r.id,
        i,
        key,
        g.type ?? 'SEMVER',
        g.introduced ?? '0',
        g.fixed ?? null,
        g.last ?? null,
        g.versions ? JSON.stringify(g.versions) : null,
      ),
    );
  }
  return stmts;
}
const addRecord = (r: Rec) => E.DB_ADVISORIES.batch(recordStatements(r));
async function addVuln(
  key: string,
  v: Partial<{
    kind: string;
    title: string;
    cvss: number;
    cvss_source: string;
    epss: number;
    kev_added: string;
    ransomware: number;
    exploit_public: number;
  }> = {},
) {
  await E.DB_VULNS.prepare(
    `INSERT INTO vulns (key, kind, title, modified, cvss, cvss_source, epss, kev_added, ransomware, exploit_public)
     VALUES (?1, ?2, ?3, '2026-01-01T00:00:00Z', ?4, ?5, ?6, ?7, ?8, ?9)`,
  )
    .bind(
      key,
      v.kind ?? 'cve',
      v.title ?? `Title of ${key}`,
      v.cvss ?? null,
      v.cvss_source ?? null,
      v.epss ?? null,
      v.kev_added ?? null,
      v.ransomware ?? 0,
      v.exploit_public ?? 0,
    )
    .run();
}
const addSignal = (key: string, kind: string, source: string) =>
  E.DB_SIGNALS.prepare(
    "INSERT INTO signals (vuln_key, kind, source, ref, first_seen) VALUES (?1, ?2, ?3, 'r', '2026-01-01T00:00:00Z')",
  )
    .bind(key, kind, source)
    .run();
const setDisplay = (source: string, display: 'hidden' | 'link' | 'full') =>
  E.SETTINGS.put(`source:${source}`, JSON.stringify({ display }));
const usage = async (user = 'user_a', day = DAY) =>
  (
    await E.DB_USERS.prepare('SELECT packages, calls FROM package_usage WHERE user_id = ?1 AND day = ?2')
      .bind(user, day)
      .first<{ packages: number; calls: number }>()
  )?.packages ?? null;
const setUsage = (user: string, day: string, packages: number) =>
  E.DB_USERS.prepare(
    'INSERT OR REPLACE INTO package_usage (user_id, day, packages, calls) VALUES (?1, ?2, ?3, 1)',
  )
    .bind(user, day, packages)
    .run();

let fetchSpy: ReturnType<typeof vi.spyOn>;
beforeEach(async () => {
  app = makeApp();
  fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    throw new Error(`unexpected outbound request: ${String(input)}`);
  });
  await E.DB_ADVISORIES.batch([
    E.DB_ADVISORIES.prepare('DELETE FROM affected'),
    E.DB_ADVISORIES.prepare('DELETE FROM package_advisories'),
  ]);
  await E.DB_USERS.prepare('DELETE FROM package_usage').run();
  await E.DB_VULNS.prepare("DELETE FROM vulns WHERE key LIKE '%-2099-%'").run();
  await E.DB_SIGNALS.prepare("DELETE FROM signals WHERE vuln_key LIKE '%-2099-%'").run();
  const keys = await E.SETTINGS.list({ prefix: 'source:' });
  for (const k of keys.keys) await E.SETTINGS.delete(k.name);
});
afterEach(() => {
  expect(fetchSpy).not.toHaveBeenCalled();
  vi.restoreAllMocks();
});

// --- access -------------------------------------------------------------------------------------

describe('access', () => {
  it('signed out: 401 with no-store', async () => {
    const res = await call({ packages: [pk('a')] }, { user: null });
    expect(res.status).toBe(401);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
  it('a Clerk session gets an answer', async () => {
    const res = await call({ packages: [pk('a')] });
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
  it('an MCP assertion with mti:read gets an answer, charged to its sub', async () => {
    const SECRET = 'mcp-test-secret';
    const id: McpIdentity = { sub: 'user_2abcdefghijk', scopes: ['mti:read'], clientId: 'client-abc' };
    const stub = async (c: any, next: any) => {
      c.set('clerkAuth', () => ({ userId: null }));
      await next();
    };
    const full = createApp(stub as never);
    const body = JSON.stringify({ packages: [pk('a'), pk('b')] });
    const requestId = crypto.randomUUID();
    const signed = await signMcpAssertion(
      SECRET,
      id,
      {
        requestId,
        method: 'POST',
        pathWithQuery: '/v1/packages/check',
        body: new TextEncoder().encode(body).buffer as ArrayBuffer,
      },
      Math.floor(Date.now() / 1000),
    );
    const ctx = createExecutionContext();
    const res = await full.fetch(
      new Request('https://ti-api.internal/v1/packages/check', {
        method: 'POST',
        body,
        headers: { 'x-request-id': requestId, ...signed },
      }),
      { ...env, MCP_HMAC_SECRET: SECRET } as never,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    expect(MCP_HEADERS.sub in signed).toBe(true);
    const today = new Date().toISOString().slice(0, 10);
    expect(await usage(id.sub, today)).toBe(2);
  });
});

// --- ranking ------------------------------------------------------------------------------------

describe('ranking bands', () => {
  type Fx = [string, () => Promise<void>, string];
  let n = 0;
  const fx = (label: string, seed: (name: string, key: string) => Promise<unknown>, want: string): Fx => [
    label,
    async () => {
      n++;
      const name = `rank-${n}`;
      await seed(name, `CVE-2099-${1000 + n}`);
      const body = await checkOne(pk(name));
      expect(body.results[0]?.priority).toBe(want);
      expect(body.summary[want]).toBe(1);
    },
    want,
  ];
  const rec = (name: string, key: string, extra: Partial<Rec> = {}) =>
    addRecord({ id: `GHSA-${key}`, key, name, ranges: [exact('1.0.0')], ...extra });
  const fixtures: Fx[] = [
    fx(
      'kev_added',
      async (name, key) => (await rec(name, key), addVuln(key, { kev_added: '2026-01-01', cvss: 5 })),
      'fix_now',
    ),
    fx(
      'exploited_wild signal, no KEV',
      async (name, key) => (
        await rec(name, key), await addVuln(key), addSignal(key, 'exploited_wild', 'cisa-kev')
      ),
      'fix_now',
    ),
    fx(
      'ransomware flag',
      async (name, key) => (await rec(name, key), addVuln(key, { ransomware: 1 })),
      'fix_now',
    ),
    fx(
      'all-versions malicious record',
      async (name, key) =>
        addRecord({
          id: key.replace('CVE', 'MAL'),
          key: key.replace('CVE', 'MAL'),
          source: 'openssf-malicious-packages',
          name,
          ranges: [allVersions],
          reviewed: 0,
        }),
      'fix_now',
    ),
    fx(
      'MAL- id from osv',
      async (name, key) =>
        addRecord({
          id: key.replace('CVE', 'MAL'),
          key: key.replace('CVE', 'MAL'),
          source: 'osv',
          name,
          ranges: [exact('1.0.0')],
        }),
      'fix_now',
    ),
    fx(
      'exploited_wild from a hidden source only, CVSS 5.0',
      async (name, key) => (
        await rec(name, key), await addVuln(key, { cvss: 5 }), addSignal(key, 'exploited_wild', 'aiid')
      ),
      'note',
    ),
    fx(
      'public_exploit signal',
      async (name, key) => (
        await rec(name, key), await addVuln(key), addSignal(key, 'public_exploit', 'metasploit')
      ),
      'fix_soon',
    ),
    fx(
      'exploit_public flag',
      async (name, key) => (await rec(name, key), addVuln(key, { exploit_public: 1 })),
      'fix_soon',
    ),
    fx(
      'poc signal',
      async (name, key) => (await rec(name, key), await addVuln(key), addSignal(key, 'poc', 'poc-in-github')),
      'fix_soon',
    ),
    fx('EPSS 0.10', async (name, key) => (await rec(name, key), addVuln(key, { epss: 0.1 })), 'fix_soon'),
    fx(
      'EPSS 0.099 with CVSS 7.0',
      async (name, key) => (await rec(name, key), addVuln(key, { epss: 0.099, cvss: 7 })),
      'plan',
    ),
    fx(
      'no vulns row, severity HIGH',
      async (name, key) => void (await rec(name, key, { severity: 'HIGH' })),
      'plan',
    ),
    fx('CVSS 6.9', async (name, key) => (await rec(name, key), addVuln(key, { cvss: 6.9 })), 'note'),
    fx('a record and nothing else', async (name, key) => void (await rec(name, key)), 'note'),
  ];
  it.each(fixtures.map((f) => [f[0], f[1]] as const))('%s', async (_l, run) => run());

  it('one note match plus one fix_now match: fix_now, matches in that order', async () => {
    await addRecord({ id: 'GHSA-n', key: 'CVE-2099-2001', name: 'mixed' });
    await addRecord({ id: 'GHSA-f', key: 'CVE-2099-2002', name: 'mixed' });
    await addVuln('CVE-2099-2002', { kev_added: '2026-01-01' });
    const body = await checkOne(pk('mixed'));
    expect(body.results[0].priority).toBe('fix_now');
    expect(body.results[0].matches.map((m: any) => m.id)).toEqual(['CVE-2099-2002', 'CVE-2099-2001']);
    expect(body.results[0].matches[0].signals).toEqual(['exploited_wild']);
  });

  it('malicious → fix_now with no comparer, no upgrade, malicious note', async () => {
    await addRecord({
      id: 'MAL-2099-1',
      source: 'openssf-malicious-packages',
      name: 'evil-pkg',
      ranges: [allVersions],
      reviewed: 0,
    });
    const body = await checkOne(pk('evil-pkg', '9.9.9'), {
      deps: { now: () => NOW, versions: { inRange, comparerFor: realComparerFor } },
    });
    const r = body.results[0];
    expect(r.priority).toBe('fix_now');
    expect(r.matches[0].signals).toContain('malicious');
    expect(r.upgradeTo).toBeNull();
    expect(r.upgradeNote).toBe(NOTE.malicious('MAL-2099-1'));
  });
});

// --- rejections ---------------------------------------------------------------------------------

const token = (...parts: string[]) => parts.join('');
const T36 = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';

describe('rejections', () => {
  it('names every reason by index, echoes nothing, and still answers the valid entries', async () => {
    await addRecord({ id: 'GHSA-ok', key: 'CVE-2099-3001', name: 'lodash' });
    const canary = 'zzcanaryvalue';
    const packages = [
      pk('lodash'),
      5,
      { ecosystem: `nope${canary}`, name: 'a', version: '1.0.0' },
      pk(`Bad ${canary} Name`),
      pk('a', `^1.${canary}`),
      { purl: `nope-${canary}` },
      pk(`a​${canary}`),
      pk(`https://evil.test/${canary}`),
      pk(token('ghp', '_', T36), '1.0.0'),
      pk('lodash'),
      pk('left-pad', '1.3.0'),
    ];
    const res = await call({ packages });
    const text = await res.text();
    const body = JSON.parse(text);
    expect(body.rejected).toEqual([
      { index: 1, reason: 'bad_entry' },
      { index: 2, reason: 'bad_ecosystem' },
      { index: 3, reason: 'bad_name' },
      { index: 4, reason: 'bad_version' },
      { index: 5, reason: 'bad_purl' },
      { index: 6, reason: 'bad_characters' },
      { index: 7, reason: 'looks_like_url' },
      { index: 8, reason: 'looks_like_secret' },
      { index: 9, reason: 'duplicate' },
    ]);
    expect(text).not.toContain(canary);
    expect(text).not.toContain('evil.test');
    expect(text).not.toContain(T36);
    expect(body.checked).toBe(2);
    expect(body.matched).toBe(1);
    expect(body.noRecord).toEqual([{ ecosystem: 'npm', name: 'left-pad', version: '1.3.0' }]);
  });

  it('answers 200 with rejected and notes only when nothing is accepted: no charge, no reads', async () => {
    const adv = vi.fn();
    const e = { ...env, DB_ADVISORIES: { prepare: adv, batch: adv } };
    const res = await call({ packages: [5, pk('A B')] }, { e });
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.rejected).toHaveLength(2);
    expect(body.notes[0]).toBe(NOTES.noRecord);
    expect(adv).not.toHaveBeenCalled();
    expect(await usage()).toBeNull();
  });

  it('refuses a non-JSON body and a bad envelope', async () => {
    for (const raw of ['nope', '{}', '{"packages":[]}', '[]', '{"packages":[],"x":1}']) {
      const res = await call(null, { raw });
      expect(res.status).toBe(400);
      expect(await json(res)).toEqual({ error: 'invalid_body' });
      expect(res.headers.get('cache-control')).toBe('no-store');
    }
  });
});

describe('secrets', () => {
  const tokens = [
    token('ghp', '_', T36),
    token('gho', '_', T36),
    token('ghu', '_', T36),
    token('ghs', '_', T36),
    token('ghr', '_', T36),
    token('github', '_pat_', T36),
    token('npm', '_', T36),
    token('sk', '-', T36),
    token('xox', 'b', '-', '1234567890-abcdef'),
    token('AKIA', 'ABCDEFGHIJKLMNOP'),
    token('glpat', '-', 'abcdefghij0123456789'),
    token('pypi', '-', `${T36}${T36}`),
    token('deploy:s3cr3t', '@registry'),
    [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    ].join('.'),
    'q8Zk3Vx9TnP2mLw7Rb4YhGc6JdF1sAe5UoXiN0Kt',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  ];
  it('every token shape is looks_like_secret', async () => {
    const body = await call({
      packages: [
        ...tokens.map((t) => pk('a', t)),
        { purl: 'pkg:npm/a@1.0.0?repository_url=https://u:p@host' },
      ],
    });
    const b = await json(body);
    expect(b.rejected.every((r: any) => r.reason === 'looks_like_secret')).toBe(true);
    expect(b.rejected).toHaveLength(tokens.length + 1);
    expect(b.checked).toBe(0);
  });
  it('the must-accept corpus is answered', async () => {
    const sha = 'a5ac7e51b41094c92402da3b24376905380afc29';
    const packages = [
      pk('actions/checkout', sha, 'GitHub Actions'),
      pk('github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5', 'v5.7.0', 'Go'),
      pk('golang.org/x/net', 'v0.0.0-20231115185253-1b2c3d4e5f60', 'Go'),
      pk('org.springframework.boot:spring-boot-starter-web', '3.2.0', 'Maven'),
      pk('Microsoft.Extensions.DependencyInjection.Abstractions', '8.0.0', 'NuGet'),
      pk('torch', '2.1.0+cu121', 'PyPI'),
      pk('pypi-simple', '1.4.0', 'PyPI'),
      pk('@typescript-eslint/eslint-plugin', '6.13.2-alpha.0'),
      pk('sk-utils', '1.0.0'),
      pk('glibc', '2.36-9+deb12u4', 'Debian:12'),
      pk('glibc', '1:2.36-9', 'Debian:12'),
      pk('openssl', '1:3.0.7-24.el9', 'Red Hat'),
      pk('nokogiri', '1.15.4-x86_64-linux', 'RubyGems'),
      pk('github.com/apple/swift-nio', '2.62.0', 'SwiftURL'),
      { purl: 'pkg:npm/left-pad@1.3.0?repository_url=https://registry.npmjs.org' },
    ];
    const b = await json(await call({ packages }));
    expect(b.rejected).toEqual([]);
    expect(b.checked).toBe(packages.length);
  });
});

describe('caps', () => {
  const many = (n: number) => ({ packages: Array.from({ length: n }, (_, i) => pk(`cap-${i}`)) });
  it('1,001 entries: 400 too_many_packages, no usage row', async () => {
    const res = await call(many(1001));
    expect(res.status).toBe(400);
    expect(await json(res)).toEqual({ error: 'too_many_packages', max: 1000 });
    expect(await usage()).toBeNull();
  });
  it('1,000 entries: 200', async () => {
    const res = await call(many(1000));
    expect(res.status).toBe(200);
    expect(await usage()).toBe(1000);
  });
  it('a body over 1 MiB: 413', async () => {
    const res = await call(null, { raw: `{"packages":["${'a'.repeat(1_100_000)}"]}` });
    expect(res.status).toBe(413);
    expect(await json(res)).toEqual({ error: 'body_too_large' });
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
});

// --- quota --------------------------------------------------------------------------------------

describe('quota', () => {
  const many = (n: number, p = 'q') => ({ packages: Array.from({ length: n }, (_, i) => pk(`${p}-${i}`)) });
  it('holds at 20,000 and refuses a call whole, with the seconds to midnight', async () => {
    const at = { now: () => new Date('2026-11-26T23:59:30Z') };
    await setUsage('user_a', DAY, 19_000);
    expect((await call(many(1000), { deps: at })).status).toBe(200);
    expect(await usage()).toBe(20_000);
    const res = await call(many(1), { deps: at });
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('30');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await json(res)).toEqual({ error: 'quota_exceeded', limit: 20000, remaining: 0, retryAfter: 30 });
  });
  it('501 more at 19,500: 429 with remaining 500 and the row unchanged', async () => {
    await setUsage('user_a', DAY, 19_500);
    const res = await call(many(501));
    expect(res.status).toBe(429);
    expect((await json(res)).remaining).toBe(500);
    expect(await usage()).toBe(19_500);
  });
  it("yesterday's full row doesn't block today", async () => {
    await setUsage('user_a', '2026-11-25', 20_000);
    expect((await call(many(5))).status).toBe(200);
    expect(await usage()).toBe(5);
  });
  it('two parallel calls of 400 at 19,500: exactly one passes', async () => {
    await setUsage('user_a', DAY, 19_500);
    const [a, b] = await Promise.all([call(many(400, 'p1')), call(many(400, 'p2'))]);
    expect([a.status, b.status].sort()).toEqual([200, 429]);
    expect(await usage()).toBe(19_900);
  });
  it("rejected entries aren't charged, and each user has their own row", async () => {
    await call({ packages: [pk('a'), pk('b'), pk('A B'), 5, pk('a')] });
    expect(await usage()).toBe(2);
    await call({ packages: [pk('a')] }, { user: 'user_b' });
    expect(await usage('user_b')).toBe(1);
    expect(await usage()).toBe(2);
  });
  it('a DB_USERS that throws: 503 quota_unavailable, and no advisories statement runs', async () => {
    const adv = vi.fn();
    const e = {
      ...env,
      DB_USERS: {
        prepare() {
          throw new Error('boom');
        },
      },
      DB_ADVISORIES: { prepare: adv, batch: adv },
    };
    const res = await call({ packages: [pk('a')] }, { e });
    expect(res.status).toBe(503);
    expect(await json(res)).toEqual({ error: 'quota_unavailable' });
    expect(res.headers.get('retry-after')).toBe('30');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(adv).not.toHaveBeenCalled();
  });
  it('a DB_ADVISORIES that throws: 500, and the charge is given back', async () => {
    await setUsage('user_a', DAY, 100);
    const e = {
      ...env,
      DB_ADVISORIES: {
        prepare: (q: string) => E.DB_ADVISORIES.prepare(q),
        batch: async () => {
          throw new Error('boom');
        },
      },
    };
    const res = await call(many(50), { e });
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: 'internal' });
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await usage()).toBe(100);
  });
});

// --- upgrade advice -----------------------------------------------------------------------------

describe('upgrade advice', () => {
  const toyDeps = { now: () => NOW, versions: toyRules } as PackagesDeps;
  const M = (v = '3') => pk('g:a', v, 'Maven');
  const range = (fixed: string | null, introduced = '0'): Range => ({ type: 'ECOSYSTEM', introduced, fixed });
  const sane = (r: any) => {
    expect(r.package).toEqual({ ecosystem: 'Maven', name: 'g:a', version: '3' });
    if (r.upgradeTo !== null) expect(r.upgradeTo).toMatch(/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/);
  };

  it('a reviewed fix above the version is offered, with source, id, date and the confirm sentence', async () => {
    await addRecord({
      id: 'GHSA-up',
      key: 'CVE-2099-4001',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('5')],
      modified: '2026-03-04T05:06:07Z',
    });
    const r = (await checkOne(M(), { deps: toyDeps })).results[0];
    sane(r);
    expect(r.upgradeTo).toBe('5');
    expect(r.matches[0].fixedIn).toBe('5');
    expect(r.upgradeNote).toBe(
      NOTE.suggestion(
        '5',
        'GitHub Advisory DB',
        'CVE-2099-4001'.replace('CVE-2099-4001', 'GHSA-up'),
        '2026-03-04',
      ),
    );
    expect(r.upgradeNote).toContain('GitHub Advisory DB');
    expect(r.upgradeNote).toContain("Confirm 5 exists in the registry and isn't brand new");
  });
  it('an unreviewed fix is never offered', async () => {
    await addRecord({
      id: 'GHSA-un',
      key: 'CVE-2099-4002',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('9')],
      reviewed: 0,
    });
    const r = (await checkOne(M(), { deps: toyDeps })).results[0];
    expect(r.matches[0].fixedIn).toBeNull();
    expect(r.upgradeTo).toBeNull();
    expect(r.upgradeNote).toBe(NOTE.noFix('CVE-2099-4002'));
  });
  it('a malicious EXACT record for the candidate stops the suggestion', async () => {
    await addRecord({
      id: 'GHSA-1',
      key: 'CVE-2099-4003',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('5')],
    });
    await addRecord({
      id: 'MAL-2099-2',
      source: 'openssf-malicious-packages',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [exact('5')],
    });
    const r = (await checkOne(M(), { deps: toyDeps })).results[0];
    sane(r);
    expect(r.upgradeTo).toBeNull();
    expect(r.upgradeNote).toBe(NOTE.candidateAffected('5'));
  });
  it('another range that starts at the candidate stops it too', async () => {
    await addRecord({
      id: 'GHSA-1',
      key: 'CVE-2099-4004',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('5')],
    });
    await addRecord({
      id: 'GHSA-2',
      key: 'CVE-2099-4005',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('7', '5')],
    });
    const r = (await checkOne(M(), { deps: toyDeps })).results[0];
    expect(r.upgradeTo).toBeNull();
    expect(r.upgradeNote).toBe(NOTE.candidateAffected('5'));
  });
  it("a candidate that can't be checked → null and the can't-check note", async () => {
    await addRecord({
      id: 'GHSA-1',
      key: 'CVE-2099-4006',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('5')],
    });
    await addRecord({
      id: 'GHSA-U',
      key: 'CVE-2099-4007',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('8', '6')],
    });
    const deps = {
      now: () => NOW,
      versions: {
        comparerFor: () => toy,
        inRange: (e: any, v: string, r: any, c: any) =>
          v === '5' && r.source_id === 'GHSA-U' ? 'unsupported' : inRange(e, v, r, c),
      },
    } as PackagesDeps;
    const r = (await checkOne(M(), { deps })).results[0];
    expect(r.upgradeTo).toBeNull();
    expect(r.upgradeNote).toBe(NOTE.cantCheck('5', 'Maven'));
  });
  it('two matches fixed in 5 and 7, with 7 clear, give 7', async () => {
    await addRecord({
      id: 'GHSA-1',
      key: 'CVE-2099-4008',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('5')],
    });
    await addRecord({
      id: 'GHSA-2',
      key: 'CVE-2099-4009',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('7')],
    });
    const r = (await checkOne(M(), { deps: toyDeps })).results[0];
    sane(r);
    expect(r.upgradeTo).toBe('7');
  });
  it('no comparer and two distinct fixes: null and the cannot-order note', async () => {
    await addRecord({
      id: 'GHSA-1',
      key: 'CVE-2099-4010',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('5')],
    });
    await addRecord({
      id: 'GHSA-2',
      key: 'CVE-2099-4011',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('7')],
    });
    const deps = {
      now: () => NOW,
      versions: { comparerFor: () => null, inRange: (_e: any, v: string) => v === '3' },
    } as PackagesDeps;
    const r = (await checkOne(M(), { deps })).results[0];
    expect(r.upgradeTo).toBeNull();
    expect(r.upgradeNote).toBe(NOTE.cantOrder('Maven'));
  });
  it('a fix that looks like another package is ignored', async () => {
    await addRecord({
      id: 'GHSA-1',
      key: 'CVE-2099-4012',
      name: 'g:a',
      ecosystem: 'Maven',
      ranges: [range('other-pkg@1.0')],
    });
    const lenient = {
      valid: () => true,
      compare: (a: string, b: string) => Number.parseFloat(a) - Number.parseFloat(b),
    };
    const deps = { now: () => NOW, versions: { inRange, comparerFor: () => lenient } } as PackagesDeps;
    const r = (await checkOne(M(), { deps })).results[0];
    sane(r);
    expect(r.matches[0].fixedIn).toBeNull();
    expect(r.upgradeTo).toBeNull();
  });
});

// --- licences -----------------------------------------------------------------------------------

describe('licence hiding', () => {
  it('a hidden source never matches and appears nowhere', async () => {
    await addRecord({ id: 'GHSA-h', key: 'CVE-2099-5001', name: 'hid', summary: 'secretsummary' });
    await setDisplay('github-advisory-db', 'hidden');
    const res = await call({ packages: [pk('hid')] });
    const text = await res.text();
    const body = JSON.parse(text);
    expect(body.noRecord).toHaveLength(1);
    expect(body.results).toEqual([]);
    expect(text).not.toContain('github-advisory-db');
    expect(text).not.toContain('GHSA-h');
    expect(body.credits).toEqual([]);
  });
  it("a hidden signal source doesn't raise priority", async () => {
    await addRecord({ id: 'GHSA-s', key: 'CVE-2099-5002', name: 'sig' });
    await addVuln('CVE-2099-5002', { cvss: 4 });
    await addSignal('CVE-2099-5002', 'exploited_wild', 'cisa-kev');
    expect((await checkOne(pk('sig'))).results[0].priority).toBe('fix_now');
    await setDisplay('cisa-kev', 'hidden');
    const r = (await checkOne(pk('sig'))).results[0];
    expect(r.priority).toBe('note');
    expect(r.matches[0].sources).not.toContain('cisa-kev');
  });
  it('a hidden cvss_source gives cvss null; a visible one gives its credit', async () => {
    await addRecord({ id: 'GHSA-c', key: 'CVE-2099-5003', name: 'cv' });
    await addVuln('CVE-2099-5003', { cvss: 9.8, cvss_source: 'nvd' });
    const seen = await checkOne(pk('cv'));
    expect(seen.results[0].matches[0].cvss).toBe(9.8);
    expect(seen.results[0].priority).toBe('plan');
    expect(seen.credits.map((c: any) => c.sourceId)).toContain('nvd');
    expect(JSON.stringify(seen.credits)).toContain('NVD API');
    await setDisplay('nvd', 'hidden');
    const hid = await checkOne(pk('cv'));
    expect(hid.results[0].matches[0].cvss).toBeNull();
    expect(hid.results[0].priority).toBe('note');
    expect(hid.credits.map((c: any) => c.sourceId)).not.toContain('nvd');
  });
  it('link mode shows id, URL and source only', async () => {
    await addRecord({
      id: 'GHSA-l',
      key: 'CVE-2099-5004',
      name: 'lnk',
      summary: 'a summary',
      severity: 'CRITICAL',
      url: 'https://example.test/adv',
      ranges: [{ type: 'EXACT', versions: ['1.0.0'], fixed: '1.0.1' }],
    });
    await setDisplay('github-advisory-db', 'link');
    const r = (await checkOne(pk('lnk'))).results[0];
    expect(r.priority).toBe('note');
    expect(r.matches[0]).toMatchObject({
      id: 'CVE-2099-5004',
      summary: null,
      fixedIn: null,
      sources: ['github-advisory-db'],
    });
    expect(r.matches[0].url).toBe('https://example.test/adv');
    expect(JSON.stringify(r)).not.toContain('a summary');
  });
  it('full mode shows the summary and falls back to the entry page, then to search', async () => {
    await addRecord({ id: 'GHSA-f1', key: 'CVE-2099-5005', name: 'url1', summary: 'plain summary' });
    await addVuln('CVE-2099-5005');
    await addRecord({ id: 'GHSA-f2', key: 'CVE-2099-5006', name: 'url2' });
    const a = (await checkOne(pk('url1'))).results[0].matches[0];
    expect(a.summary).toBe('plain summary');
    expect(a.url).toBe('https://mti.motiontic.com/e/CVE-2099-5005');
    const b = (await checkOne(pk('url2'))).results[0].matches[0];
    expect(b.url).toBe('https://mti.motiontic.com/search?q=CVE-2099-5006');
  });
});

describe('dependency confusion', () => {
  it('a private name with a public malicious record is a confusion warning, not a result', async () => {
    await addRecord({
      id: 'MAL-2099-3',
      source: 'openssf-malicious-packages',
      name: 'internal-lib',
      ranges: [allVersions],
      reviewed: 0,
    });
    const body = await checkOne({ ...pk('internal-lib', '0.0.1'), private: true });
    expect(body.results).toEqual([]);
    expect(body.uncertain).toEqual([]);
    expect(body.confusion).toEqual([
      {
        package: { ecosystem: 'npm', name: 'internal-lib', version: '0.0.1' },
        ids: ['MAL-2099-3'],
        reason: 'public_malicious_name',
      },
    ]);
    expect(body.notes).toContain(NOTES.private);
    const pub = await checkOne(pk('internal-lib', '0.0.1'));
    expect(pub.results[0].priority).toBe('fix_now');
    expect(pub.confusion).toEqual([]);
  });
  it('a private name with only ordinary advisories is noRecord', async () => {
    await addRecord({ id: 'GHSA-p', key: 'CVE-2099-5100', name: 'internal-lib' });
    const body = await checkOne({ ...pk('internal-lib'), private: true });
    expect(body.noRecord).toHaveLength(1);
    expect(body.results).toEqual([]);
    expect(body.confusion).toEqual([]);
  });
});

describe('uncertain path', () => {
  const stub = {
    now: () => NOW,
    versions: { comparerFor: realComparerFor, inRange: () => 'unsupported' },
  } as PackagesDeps;
  it('is listed under uncertain, not noRecord, with note 4', async () => {
    await addRecord({
      id: 'GHSA-u',
      key: 'CVE-2099-5200',
      name: 'unc',
      ranges: [{ type: 'SEMVER', introduced: '0', fixed: '2.0.0' }],
    });
    const body = await checkOne(pk('unc'), { deps: stub });
    expect(body.results).toEqual([]);
    expect(body.noRecord).toEqual([]);
    expect(body.uncertain).toEqual([
      {
        package: { ecosystem: 'npm', name: 'unc', version: '1.0.0' },
        ids: ['CVE-2099-5200'],
        reason: 'version_rules_pending',
      },
    ]);
    expect(body.notes).toContain(NOTES.uncertain);
  });
  it('one matched and one uncertain record: in both lists', async () => {
    await addRecord({
      id: 'GHSA-m',
      key: 'CVE-2099-5201',
      name: 'both',
      ranges: [{ type: 'SEMVER', introduced: '0' }],
    });
    await addRecord({
      id: 'GHSA-n',
      key: 'CVE-2099-5202',
      name: 'both',
      ranges: [{ type: 'SEMVER', introduced: '0', fixed: '2.0.0' }],
    });
    const body = await checkOne(pk('both'), { deps: stub });
    expect(body.results[0].matches.map((m: any) => m.id)).toEqual(['CVE-2099-5201']);
    expect(body.uncertain[0].ids).toEqual(['CVE-2099-5202']);
  });
});

describe('headers and notes', () => {
  it('every answer is no-store, and every 200 has note 1, word for word', async () => {
    const ok = await call({ packages: [pk('a')] });
    expect((await json(ok)).notes[0]).toBe('No record means none in MTI as of asOf. It does not mean safe.');
    const all = await call({ packages: [5] });
    expect((await json(all)).notes[0]).toBe('No record means none in MTI as of asOf. It does not mean safe.');
    const statuses = [ok, all, await call(null, { raw: 'x' }), await call(null, { user: null, raw: '{}' })];
    for (const r of statuses) expect(r.headers.get('cache-control')).toBe('no-store');
    expect(statuses.map((r) => r.status)).toEqual([200, 200, 400, 401]);
  });
  it('notes appear in order, and the optional ones only when they apply', async () => {
    const plain = await checkOne(pk('a'));
    expect(plain.notes).toEqual([NOTES.noRecord, NOTES.reachability, NOTES.fixes, NOTES.sources]);
    const priv = await checkOne({ ...pk('a'), private: true });
    expect(priv.notes).toEqual([
      NOTES.noRecord,
      NOTES.reachability,
      NOTES.fixes,
      NOTES.private,
      NOTES.sources,
    ]);
  });
  it('bare Debian needs a release and says so', async () => {
    const body = await json(
      await call({ packages: [pk('curl', '7.0', 'Debian'), pk('curl', '7.88.1-10', 'Debian:12')] }),
    );
    expect(body.rejected).toEqual([{ index: 0, reason: 'bad_ecosystem' }]);
    expect(body.notes).toContain(NOTES.release);
    expect(body.checked).toBe(1);
  });
  it('OS rows are matched by their full key', async () => {
    await addRecord({
      id: 'DSA-1',
      key: 'CVE-2099-5300',
      name: 'curl',
      ecosystem: 'Debian:12',
      source: 'osv',
      ranges: [exact('7.88.1-10')],
    });
    const body = await json(
      await call({ packages: [pk('curl', '7.88.1-10', 'Debian:12'), pk('curl', '7.88.1-10', 'Debian:11')] }),
    );
    expect(body.results).toHaveLength(1);
    expect(body.results[0].package.ecosystem).toBe('Debian:12');
    expect(body.noRecord).toHaveLength(1);
  });
});

// --- logs ---------------------------------------------------------------------------------------

describe('logs', () => {
  const FIELDS = new Set([
    'level',
    'event',
    'requestId',
    'outcome',
    'checked',
    'matched',
    'rejected',
    'uncertain',
    'confusion',
    'unknownNames',
    'ecosystems',
    'ms',
    'msQuota',
    'msLookup',
    'msMatch',
  ]);
  const stub = async (c: any, next: any) => {
    c.set('clerkAuth', () => ({ userId: c.req.header('x-test-user') ?? null }));
    await next();
  };
  const full = createApp(stub as never);
  const ctx = { waitUntil: () => {}, passThroughException() {} } as unknown as ExecutionContext;

  it('writes one packages_check line per call, with counts and timing only, and no canary anywhere', async () => {
    const lines: string[] = [];
    for (const m of ['log', 'warn', 'error'] as const)
      vi.spyOn(console, m).mockImplementation((s: unknown) => void lines.push(String(s)));
    await addRecord({
      id: 'GHSA-canary-7777',
      key: 'CVE-2099-7777',
      name: 'canary-pkg-name',
      ranges: [exact('7.7.7')],
    });
    const post = (packages: unknown[], e: object = env) =>
      full.fetch(
        new Request('https://api.test/v1/packages/check', {
          method: 'POST',
          headers: { 'x-test-user': 'user_log' },
          body: JSON.stringify({ packages }),
        }),
        e as never,
        ctx,
      );
    const canaryPurl = 'pkg:npm/canary-purl-name@7.7.7';
    const before = () => lines.filter((l) => l.includes('"packages_check"')).length;

    expect((await post([pk('canary-pkg-name', '7.7.7'), { purl: canaryPurl }])).status).toBe(200);
    expect(before()).toBe(1);
    expect(
      (await post([pk('canary-bad-name', '7.7.7'.replace('7', 'x')), pk(token('ghp', '_', T36))])).status,
    ).toBe(200);
    expect(before()).toBe(2);
    await setUsage('user_log', new Date().toISOString().slice(0, 10), 20_000);
    expect((await post([pk('canary-pkg-name', '7.7.7')])).status).toBe(429);
    expect(before()).toBe(3);
    const bad = {
      ...env,
      DB_USERS: {
        prepare() {
          throw new Error('canary-d1-error');
        },
      },
    };
    await E.DB_USERS.prepare('DELETE FROM package_usage').run();
    expect((await post([pk('canary-pkg-name', '7.7.7')], bad)).status).toBe(503);
    expect(before()).toBe(4);
    const bad2 = {
      ...env,
      DB_ADVISORIES: {
        prepare: (q: string) => E.DB_ADVISORIES.prepare(q),
        batch: async () => {
          throw new Error('canary-d1-error');
        },
      },
    };
    expect((await post([pk('canary-pkg-name', '7.7.7')], bad2)).status).toBe(500);
    expect(before()).toBe(5);

    const all = lines.join('\n');
    for (const canary of [
      'canary-pkg-name',
      'canary-purl-name',
      'canary-bad-name',
      '7.7.7',
      'CVE-2099-7777',
      'GHSA-canary',
      'canary-d1-error',
      T36,
    ])
      expect(all).not.toContain(canary);
    const parsed = lines.map((l) => JSON.parse(l));
    const pc = parsed.filter((l) => l.event === 'packages_check');
    expect(pc.map((l) => l.outcome)).toEqual([
      'ok',
      'all_rejected',
      'quota_exceeded',
      'quota_unavailable',
      'failed',
    ]);
    for (const l of pc) for (const k of Object.keys(l)) expect(FIELDS.has(k), k).toBe(true);
    expect(pc[0]).toMatchObject({ checked: 2, matched: 1, rejected: 0, ecosystems: 1, unknownNames: 1 });
    expect(pc[1]).toMatchObject({ checked: 0 + 1 - 1, rejected: 2 });
  });
});

// --- scale and plans ----------------------------------------------------------------------------

describe('scale', () => {
  it('500 names in one ecosystem: 5 advisory statements in one batch, one batch each for vulns and signals', async () => {
    const stmts: D1PreparedStatement[] = [];
    for (let i = 0; i < 600; i++) {
      for (let k = 0; k < 5; k++) {
        stmts.push(
          ...recordStatements({
            id: `GHSA-sc-${i}-${k}`,
            key: `CVE-2099-${i}-${k}`,
            name: `scale-${i}`,
            ranges: [exact(k === 0 ? '1.0.0' : `2.${k}.0`)],
          }),
        );
      }
    }
    for (let i = 0; i < stmts.length; i += 90) await E.DB_ADVISORIES.batch(stmts.slice(i, i + 90));
    const calls: Record<string, number[]> = { adv: [], vulns: [], signals: [] };
    const wrap = (db: D1Database, k: string) => ({
      prepare: (q: string) => db.prepare(q),
      batch: (s: D1PreparedStatement[]) => (calls[k]?.push(s.length), db.batch(s)),
    });
    const e = {
      ...env,
      DB_ADVISORIES: wrap(E.DB_ADVISORIES, 'adv'),
      DB_VULNS: wrap(E.DB_VULNS, 'vulns'),
      DB_SIGNALS: wrap(E.DB_SIGNALS, 'signals'),
    };
    const packages = Array.from({ length: 500 }, (_, i) => pk(`scale-${i}`));
    const res = await call({ packages }, { e });
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.checked).toBe(500);
    expect(body.matched).toBe(500);
    expect(body.results.every((r: any) => r.matches.length === 1 && r.omitted === 0)).toBe(true);
    expect(body.noRecord).toEqual([]);
    expect(calls.adv).toEqual([5]);
    expect(calls.vulns).toHaveLength(1);
    expect(calls.signals).toHaveLength(1);
    expect(calls.vulns?.[0]).toBe(25);
  }, 60_000);

  it('keeps the first 50 matches and counts the rest as omitted', async () => {
    for (let i = 0; i < 53; i++)
      await addRecord({ id: `GHSA-om-${i}`, key: `CVE-2099-9${String(i).padStart(3, '0')}`, name: 'many' });
    const r = (await checkOne(pk('many'))).results[0];
    expect(r.matches).toHaveLength(50);
    expect(r.omitted).toBe(3);
  });
});

describe('query plans', () => {
  const plan = async (db: D1Database, sql: string, ...args: unknown[]) =>
    (
      (
        await db
          .prepare(`EXPLAIN QUERY PLAN ${sql}`)
          .bind(...args)
          .all<{ detail: string }>()
      ).results ?? []
    ).map((r) => r.detail);
  it('every lookup statement is an index search', async () => {
    const a = await plan(E.DB_ADVISORIES, AFFECTED_SQL, 'npm', '["x"]');
    const v = await plan(E.DB_VULNS, VULNS_SQL, '["x"]');
    const s = await plan(E.DB_SIGNALS, SIGNALS_SQL, '["x"]');
    expect(a.some((d) => /SEARCH a USING PRIMARY KEY/.test(d))).toBe(true);
    expect(a.some((d) => /SEARCH p USING PRIMARY KEY/.test(d))).toBe(true);
    expect(v.some((d) => /SEARCH vulns USING PRIMARY KEY/.test(d))).toBe(true);
    expect(s.some((d) => /SEARCH signals USING PRIMARY KEY/.test(d))).toBe(true);
    for (const d of [...a, ...v, ...s])
      expect(d).not.toMatch(/SCAN (a|p|affected|package_advisories|vulns|signals)\b/);
  });
});
