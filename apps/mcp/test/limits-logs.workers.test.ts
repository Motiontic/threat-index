import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { clientIp, DEFAULT_ANON_EXEMPT_CIDRS, ipInCidrs, parseCidrs } from '../src/rate-limit';
import { fakeApi, ok, withApi } from './support/fake-api';
import * as F from './support/fixtures';
import { BASE_ENV, bodyOf, modernCall, send } from './support/mcp';
import { goodPayload, type JwksSpy, makeKey, mockJwks, signJwt, type TestKey } from './support/tokens';

let key: TestKey;
let jwks: JwksSpy | undefined;
const now = () => Math.floor(Date.now() / 1000);
beforeAll(async () => {
  key = await makeKey('k1');
});
afterEach(() => {
  jwks?.restore();
  jwks = undefined;
  vi.restoreAllMocks();
  resetJwksCacheForTests();
});
const limiter = (success: boolean) => ({ limit: async () => ({ success }) });
const tokenFor = (sub = 'user_2abcdefghijk', clientId = 'client-abc') =>
  signJwt(key, goodPayload({ sub, client_id: clientId }, now()));

describe('limits', () => {
  it('the user limiter failing → 429 -31006 with Retry-After', async () => {
    jwks = mockJwks([key]);
    const c = modernCall(await tokenFor(), 'tools/list');
    const res = await send({ headers: c.headers, body: c.body }, {
      ...BASE_ENV,
      RL_MCP: limiter(false),
    } as never);
    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBe('60');
    expect(((await res.json()) as any).error.code).toBe(-31006);
  });
  it('the user limiter is keyed u:<sub>', async () => {
    jwks = mockJwks([key]);
    const keys: string[] = [];
    const rl = { limit: async (o: { key: string }) => (keys.push(o.key), { success: true }) };
    const c = modernCall(await tokenFor('user_2zzzzzzzzzz'), 'tools/list');
    await send(
      { headers: c.headers, body: c.body },
      withApi(
        { ...BASE_ENV, RL_MCP: rl } as never,
        fakeApi(() => ok({})),
      ),
    );
    expect(keys).toEqual(['u:user_2zzzzzzzzzz']);
  });
  it('a limiter error lets the request through', async () => {
    jwks = mockJwks([key]);
    const c = modernCall(await tokenFor(), 'tools/list');
    const res = await send({ headers: c.headers, body: c.body }, {
      ...BASE_ENV,
      RL_MCP: {
        limit: async () => {
          throw new Error('x');
        },
      },
    } as never);
    expect(res.status).toBe(200);
  });
  const anon = { ...BASE_ENV, RL_MCP_ANON: limiter(false) } as typeof BASE_ENV;
  it('the anonymous limiter → 429 on a token-less POST, the metadata and the card', async () => {
    const c = modernCall(undefined, 'tools/list');
    const post = await send({ headers: c.headers, body: c.body }, anon);
    expect(post.status).toBe(429);
    expect((await send({ method: 'GET' }, anon, '/.well-known/oauth-protected-resource/mcp')).status).toBe(
      429,
    );
    expect((await send({ method: 'GET' }, anon, '/mcp/server-card')).status).toBe(429);
    expect(
      (await send({ method: 'OPTIONS', headers: { origin: 'https://app.allowed.test' } }, anon)).status,
    ).toBe(429);
  });
  it('an IP in 160.79.104.0/21 skips it; others do not', async () => {
    const c = modernCall(undefined, 'tools/list');
    const exempt = await send(
      { headers: { ...c.headers, 'cf-connecting-ip': '160.79.105.7' }, body: c.body },
      anon,
    );
    expect(exempt.status).toBe(401);
    const other = await send(
      { headers: { ...c.headers, 'cf-connecting-ip': '8.8.8.8' }, body: c.body },
      anon,
    );
    expect(other.status).toBe(429);
  });
  it('MCP_ANON_EXEMPT_CIDRS replaces the default list', async () => {
    const c = modernCall(undefined, 'tools/list');
    const env = { ...anon, MCP_ANON_EXEMPT_CIDRS: '10.0.0.0/8' } as never;
    expect(
      (await send({ headers: { ...c.headers, 'cf-connecting-ip': '160.79.105.7' }, body: c.body }, env))
        .status,
    ).toBe(429);
    expect(
      (await send({ headers: { ...c.headers, 'cf-connecting-ip': '10.1.2.3' }, body: c.body }, env)).status,
    ).toBe(401);
  });
  it('an IPv6 range works', async () => {
    const c = modernCall(undefined, 'tools/list');
    const env = { ...anon, MCP_ANON_EXEMPT_CIDRS: '2001:db8::/32' } as never;
    expect(
      (await send({ headers: { ...c.headers, 'cf-connecting-ip': '2001:db8:1::5' }, body: c.body }, env))
        .status,
    ).toBe(401);
    expect(
      (await send({ headers: { ...c.headers, 'cf-connecting-ip': '2001:db9::5' }, body: c.body }, env))
        .status,
    ).toBe(429);
  });
  it('the anon limiter is keyed ip:<ip>, and ip:unknown without one', async () => {
    const keys: string[] = [];
    const env = {
      ...BASE_ENV,
      RL_MCP_ANON: { limit: async (o: { key: string }) => (keys.push(o.key), { success: true }) },
    } as never;
    const c = modernCall(undefined, 'tools/list');
    await send({ headers: { ...c.headers, 'cf-connecting-ip': '8.8.4.4' }, body: c.body }, env);
    await send({ headers: c.headers, body: c.body }, env);
    await send({ headers: { ...c.headers, 'cf-connecting-ip': 'not-an-ip' }, body: c.body }, env);
    expect(keys).toEqual(['ip:8.8.4.4', 'ip:unknown', 'ip:unknown']);
  });
  it('cidr helpers', () => {
    expect(parseCidrs('1.2.3.0/24, bad, 1.2.3.4/33, ::1/128').length).toBe(2);
    expect(ipInCidrs('153.61.208.1', parseCidrs(DEFAULT_ANON_EXEMPT_CIDRS.join(',')))).toBe(true);
    expect(ipInCidrs('153.61.224.1', parseCidrs(DEFAULT_ANON_EXEMPT_CIDRS.join(',')))).toBe(false);
    expect(clientIp(new Request('https://x.test', { headers: { 'cf-connecting-ip': '1.2.3.4' } }))).toBe(
      '1.2.3.4',
    );
    expect(clientIp(new Request('https://x.test', { headers: { 'cf-connecting-ip': 'evil' } }))).toBeNull();
  });
});

describe('config', () => {
  it('a bad variable → 503 -31009 and an error log naming it, never its value', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const c = modernCall(undefined, 'tools/list');
    const res = await send({ headers: c.headers, body: c.body }, {
      ...BASE_ENV,
      CLERK_ISSUER: 'http://insecure.example/',
    } as never);
    expect(res.status).toBe(503);
    expect(((await res.json()) as any).error.code).toBe(-31009);
    const logged = err.mock.calls.map((a) => String(a[0])).join('\n');
    expect(logged).toContain('CLERK_ISSUER');
    expect(logged).not.toContain('insecure.example');
    const noSecret = await send({ headers: c.headers, body: c.body }, {
      ...BASE_ENV,
      MCP_HMAC_SECRET: undefined,
    } as never);
    expect(noSecret.status).toBe(503);
  });
});

describe('logs', () => {
  const CANARY = 'CANARY-ZZZ-9876';
  const spyConsole = () => {
    const lines: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const)
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void lines.push(a.map(String).join(' ')));
    return lines;
  };
  const TP = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';

  it('one mcp_request line per request, with the right fields, and no canary anywhere', async () => {
    jwks = mockJwks([key]);
    const token = await tokenFor('user_2abcdefghijk', 'client-abc');
    const api = fakeApi((req) => {
      const p = new URL(req.url).pathname;
      if (p === '/v1/home') return ok(F.home);
      if (p.startsWith('/v1/entries'))
        return ok({ ...F.entryFull, entry: { ...F.entryFull.entry, title: CANARY } });
      if (p === '/v1/search')
        return ok({ ...F.searchBody, hits: [{ ...F.searchBody.hits[0], title: CANARY }] });
      if (p === '/v1/breaches') return ok(F.breachPage(1, 3));
      if (p === '/v1/incidents') return ok(F.incidentPage);
      if (p.startsWith('/v1/techniques')) return ok(F.technique);
      if (p === '/v1/sources') return ok(F.sources);
      return ok(F.checkBody(2));
    });
    const calls: [string, Record<string, unknown>][] = [
      [
        'mti_check_packages',
        {
          packages: [
            { ecosystem: 'npm', name: 'left-pad', version: '1.0.0' },
            { ecosystem: 'npm', name: CANARY, version: '1.0.0' },
            { purl: `pkg:pypi/${CANARY}@1` },
          ],
        },
      ],
      ['mti_get_entry', { id: 'CVE-2026-0001' }],
      ['mti_search', { query: CANARY }],
      ['mti_latest_threats', { kind: 'exploited' }],
      ['mti_search_breaches', { query: CANARY }],
      ['mti_search_incidents', { query: CANARY }],
      ['mti_get_technique', { id: 'T1059' }],
      ['mti_list_sources', {}],
    ];
    const lines = spyConsole();
    for (const [name, args] of calls) {
      const c = modernCall(token, 'tools/call', { name, arguments: args, _meta: { traceparent: TP } });
      const before = lines.length;
      const res = await send(
        { headers: { ...c.headers, 'cf-connecting-ip': '203.0.113.9' }, body: c.body },
        withApi(BASE_ENV, api),
      );
      expect(res.status, name).toBe(200);
      const mine = lines.slice(before).filter((l) => l.includes('"mcp_request"'));
      expect(mine, name).toHaveLength(1);
      const line = JSON.parse(mine[0]!);
      expect(line).toMatchObject({
        event: 'mcp_request',
        route: 'mcp',
        tool: name,
        status: 200,
        sub: 'user_2abcdefghijk',
        clientId: 'client-abc',
        traceparent: TP,
        method: 'tools/call',
        era: 'modern',
      });
      expect(line.requestId).toBeTruthy();
      expect(typeof line.ms).toBe('number');
      expect(line.toolsHash).toMatch(/^[0-9a-f]{12}$/);
      if (name !== 'mti_list_sources') expect(typeof line.nOut).toBe('number');
    }
    const all = lines.join('\n');
    expect(all).not.toContain(CANARY);
    expect(all).not.toContain('203.0.113.9');
    expect(all).not.toContain(token);
    expect(all).not.toContain('evil.test');
    const pk = lines
      .map((l) => (l.includes('mti_check_packages') && l.includes('mcp_request') ? JSON.parse(l) : null))
      .find(Boolean);
    expect(pk.nIn).toBe(3);
    expect(pk.ecosystems).toBe('npm');
  });

  it('an invalid traceparent is dropped; a canary token is never logged', async () => {
    jwks = mockJwks([key]);
    const lines = spyConsole();
    const token = await tokenFor();
    const c = modernCall(token, 'tools/call', {
      name: 'mti_list_sources',
      arguments: {},
      _meta: { traceparent: `${CANARY}-bad` },
    });
    await send(
      { headers: c.headers, body: c.body },
      withApi(
        BASE_ENV,
        fakeApi(() => ok(F.sources)),
      ),
    );
    const line = JSON.parse(lines.find((l) => l.includes('mcp_request'))!);
    expect(line.traceparent).toBeUndefined();
    expect(lines.join('\n')).not.toContain(CANARY);
    const bad = modernCall(`${CANARY}.x.y`, 'tools/list');
    lines.length = 0;
    await send({ headers: bad.headers, body: bad.body });
    expect(lines.join('\n')).not.toContain(CANARY);
    expect(lines.filter((l) => l.includes('mcp_request'))).toHaveLength(1);
  });

  it('one line for a legacy SSE request, written when the stream ends', async () => {
    jwks = mockJwks([key]);
    const lines = spyConsole();
    const token = await tokenFor();
    const res = await send({
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    await bodyOf(res);
    const mine = lines.filter((l) => l.includes('mcp_request'));
    expect(mine).toHaveLength(1);
    expect(JSON.parse(mine[0]!)).toMatchObject({
      era: 'legacy',
      method: 'tools/list',
      status: 200,
      outcome: 'ok',
    });
  });
});

describe('isolation', () => {
  it('two users at the same time each reach ti-api with their own sub and get their own answer', async () => {
    jwks = mockJwks([key]);
    const ta = await tokenFor('user_2aaaaaaaaaaa', 'client-a');
    const tb = await tokenFor('user_2bbbbbbbbbbb', 'client-b');
    const api = fakeApi(async (req) => {
      const sub = req.headers.get('x-ti-mcp-sub');
      await new Promise((r) => setTimeout(r, sub === 'user_2aaaaaaaaaaa' ? 40 : 5));
      return ok({ ...F.entryFull, entry: { ...F.entryFull.entry, title: `title for ${sub}` } });
    });
    const env = withApi(BASE_ENV, api);
    const mk = async (t: string) => {
      const c = modernCall(t, 'tools/call', { name: 'mti_get_entry', arguments: { id: 'CVE-2026-0001' } });
      return bodyOf(await send({ headers: c.headers, body: c.body }, env));
    };
    const [a, b] = await Promise.all([mk(ta), mk(tb)]);
    expect(a.result.structuredContent.untrusted.title).toBe('title for user_2aaaaaaaaaaa');
    expect(b.result.structuredContent.untrusted.title).toBe('title for user_2bbbbbbbbbbb');
    const subs = api.calls.map((c) => [c.headers['x-ti-mcp-sub'], c.headers['x-ti-mcp-client']]).sort();
    expect(subs).toEqual([
      ['user_2aaaaaaaaaaa', 'client-a'],
      ['user_2bbbbbbbbbbb', 'client-b'],
    ]);
  });
});
