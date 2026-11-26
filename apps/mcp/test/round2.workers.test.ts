import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { getSigningKey, resetJwksCacheForTests } from '../src/auth/jwks';
import { clean } from '../src/clean';
import { mtiLink } from '../src/links';
import { fakeApi, ok, withApi } from './support/fake-api';
import * as F from './support/fixtures';
import { BASE_ENV, bodyOf, legacyHeaders, modernCall, send } from './support/mcp';
import {
  goodPayload,
  ISS,
  JWKS_URL,
  type JwksSpy,
  makeKey,
  mockJwks,
  SUB,
  signJwt,
  type TestKey,
} from './support/tokens';

let key: TestKey;
beforeAll(async () => {
  key = await makeKey('k1');
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  resetJwksCacheForTests();
});

const list = (token: string | undefined, env = BASE_ENV) => {
  const c = modernCall(token, 'tools/list');
  return send({ headers: c.headers, body: c.body }, env);
};
const WWW = (res: Response) => res.headers.get('www-authenticate') ?? '';
const now = () => Math.floor(Date.now() / 1000);

describe('token matrix, round 2', () => {
  it('accepts application/at+jwt, an aud array holding the URL, and expiry 4 s ago', async () => {
    const spy = mockJwks([key]);
    const env = withApi(
      BASE_ENV,
      fakeApi(() => ok({})),
    );
    for (const [header, over] of [
      [{ typ: 'application/at+jwt' }, {}],
      [{}, { aud: ['https://other.test', 'https://mti.test/mcp'] }],
      [{}, { exp: now() - 4, iat: now() - 100 }],
    ] as const) {
      const res = await list(await signJwt(key, goodPayload({ ...over }), { ...header }), env);
      expect(res.status, JSON.stringify([header, over])).toBe(200);
    }
    spy.restore();
  });

  it('scopes only in scp → no scopes → 403', async () => {
    const spy = mockJwks([key]);
    const res = await list(await signJwt(key, goodPayload({ scope: undefined, scp: ['mti:read'] })));
    expect(res.status).toBe(403);
    expect(WWW(res)).toContain('insufficient_scope');
    spy.restore();
  });

  const bad: [string, () => Promise<string>][] = [
    ['missing kid', () => signJwt(key, goodPayload(), { kid: undefined })],
    ['129-character kid', () => signJwt(key, goodPayload(), { kid: 'k'.repeat(129) })],
    ['missing exp', () => signJwt(key, goodPayload({ exp: undefined }))],
    ['missing iat', () => signJwt(key, goodPayload({ iat: undefined }))],
  ];
  it.each(bad)('%s → 401 invalid_token', async (_n, make) => {
    const spy = mockJwks([key]);
    const res = await list(await make());
    expect(res.status).toBe(401);
    expect(WWW(res)).toContain('error="invalid_token"');
    spy.restore();
  });

  it('a payload failure makes zero JWKS fetches', async () => {
    const spy = mockJwks([key]);
    const res = await list(await signJwt(key, goodPayload({ aud: 'https://elsewhere.test/mcp' })));
    expect(res.status).toBe(401);
    expect(spy.calls).toHaveLength(0);
    spy.restore();
  });
});

describe('JWKS keys, round 2', () => {
  it('the fetch carries a timeout signal and manual redirects, and only the issuer URL', async () => {
    const seen: RequestInit[] = [];
    const real = await makeKey('k1');
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      expect(String(input)).toBe(JWKS_URL);
      seen.push(init ?? {});
      return Response.json({ keys: [{ ...real.publicJwk, kid: 'k1', use: 'sig', alg: 'RS256' }] });
    });
    expect(await getSigningKey(ISS, 'k1')).toBeTruthy();
    expect(seen).toHaveLength(1);
    expect(seen[0]?.signal).toBeInstanceOf(AbortSignal);
    expect(seen[0]?.redirect).toBe('manual');
  });

  it('refuses a body over 64 KiB', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () => new Response(JSON.stringify({ keys: [], pad: 'x'.repeat(70_000) }), { status: 200 }),
    );
    await expect(getSigningKey(ISS, 'k1')).rejects.toThrow();
  });

  it('serves the last good keys for 60 minutes past expiry, logs jwks_stale, then answers 503', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const t0 = new Date('2026-11-26T10:00:00Z');
    vi.setSystemTime(t0);
    const spy: JwksSpy = mockJwks([key]);
    const env = withApi(
      BASE_ENV,
      fakeApi(() => ok({})),
    );
    const token = await signJwt(key, goodPayload({ exp: now() + 6 * 3600 }));
    expect((await list(token, env)).status).toBe(200);
    expect(spy.calls).toHaveLength(1);
    spy.mode = '500';
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // 11 minutes: past the 10-minute freshness, inside the grace window.
    vi.setSystemTime(new Date(t0.getTime() + 11 * 60_000));
    expect((await list(token, env)).status).toBe(200);
    expect(warn.mock.calls.flat().join(' ')).toContain('jwks_stale');
    // 71 minutes: past the grace window.
    vi.setSystemTime(new Date(t0.getTime() + 71 * 60_000));
    const res = await list(token, env);
    expect(res.status).toBe(503);
    expect(WWW(res)).toBe('');
    spy.restore();
  });

  it('an unknown-kid refresh that fails → 503', async () => {
    const spy = mockJwks([key]);
    const env = withApi(
      BASE_ENV,
      fakeApi(() => ok({})),
    );
    expect((await list(await signJwt(key), env)).status).toBe(200);
    spy.mode = '500';
    // A refresh is allowed once every 30 s; just inside that gap the kid is simply unknown.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 31_000));
    const res = await list(await signJwt(key, goodPayload(), { kid: 'unknown-kid' }), env);
    expect(res.status).toBe(503);
    spy.restore();
  });
});

describe('failure handling', () => {
  it('an unexpected error in the router → 500 JSON-RPC error with security headers and request ID', async () => {
    const env = {
      ...BASE_ENV,
      get MCP_ALLOWED_ORIGINS(): string {
        throw new Error('boom: SECRET-CANARY');
      },
    } as typeof BASE_ENV;
    const res = await send({ headers: { 'content-type': 'application/json' }, body: '{}' }, env);
    expect(res.status).toBe(500);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-request-id')).toBeTruthy();
    const text = await res.text();
    const b = JSON.parse(text);
    expect(b.error.code).toBe(-32603);
    expect(b.error.data.requestId).toBeTruthy();
    expect(text).not.toContain('SECRET-CANARY');
  });

  it('the metadata route answers 503 when the issuer is missing', async () => {
    const res = await send(
      { method: 'GET' },
      { ...BASE_ENV, CLERK_ISSUER: '' } as typeof BASE_ENV,
      '/.well-known/oauth-protected-resource/mcp',
    );
    expect(res.status).toBe(503);
  });
});

describe('limits, round 2', () => {
  it('the anonymous limiter keys IPv6 by /64', async () => {
    const keys: string[] = [];
    const env = {
      ...BASE_ENV,
      RL_MCP_ANON: { limit: async (o: { key: string }) => (keys.push(o.key), { success: true }) },
    } as unknown as typeof BASE_ENV;
    for (const ip of ['2001:db8:1:2:aaaa::1', '2001:db8:1:2:bbbb::9', '203.0.113.9']) {
      const c = modernCall(undefined, 'tools/list');
      await send({ headers: { ...c.headers, 'cf-connecting-ip': ip }, body: c.body }, env);
    }
    expect(keys[0]).toBe(keys[1]);
    expect(keys[0]).toBe('ip:2001:db8:1:2');
    expect(keys[2]).toBe('ip:203.0.113.9');
  });

  it('legacy era: a call whose params.name differs from a present Mcp-Name header is refused', async () => {
    const spy = mockJwks([key]);
    const api = fakeApi(() => ok({ sources: [] }));
    const env = withApi(BASE_ENV, api);
    const token = await signJwt(key);
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'mti_list_sources', arguments: {} },
    });
    const mismatch = await send(
      { headers: { ...legacyHeaders(token), 'mcp-name': 'mti_search' }, body },
      env,
    );
    expect(mismatch.status).toBe(400);
    expect((await bodyOf(mismatch)).error.code).toBe(-32020);
    expect(api.calls).toHaveLength(0);
    const match = await send(
      { headers: { ...legacyHeaders(token), 'mcp-name': 'mti_list_sources' }, body },
      env,
    );
    expect(match.status).toBe(200);
    spy.restore();
  });
});

describe('typed fields with hostile text', () => {
  it('dates, package names and link paths never carry markup or links', async () => {
    const spy = mockJwks([key]);
    const evil = 'x](https://evil.test/p.png)<b>';
    const entry = structuredClone(F.entryFull) as any;
    entry.entry.published = evil;
    entry.entry.modified = '2026-02-03T00:00:00Z<script>';
    entry.entry.kevAdded = '2026-02-01 and more';
    entry.entry.advisories[0].affected = [
      { ecosystem: 'npm', name: 'https://evil.test/x', fixed: '1.0.0' },
      { ecosystem: 'Go', name: 'evil.test/path/pkg', fixed: '1.0.0' },
      { ecosystem: 'npm', name: '//evil.test/x', fixed: '1.0.0' },
      { ecosystem: 'Maven', name: 'org.apache:commons', fixed: '1.0.0' },
      { ecosystem: 'npm', name: '@scope/pkg', fixed: '1.0.0' },
    ];
    entry.entry.advisories[0].url = 'https://www.cisa.gov/news-events/x)![a](https://evil.test/p.png)';
    entry.entry.key = 'CVE-2026-0001';
    const api = fakeApi(() => ok(entry));
    const token = await signJwt(key);
    const c = modernCall(token, 'tools/call', { name: 'mti_get_entry', arguments: { id: 'CVE-2026-0001' } });
    const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api));
    const sc = (await bodyOf(res)).result.structuredContent;
    expect(sc.published).toBeNull();
    expect(sc.modified).toBeNull();
    expect(sc.kevAdded).toBeNull();
    expect(sc.fixes.map((f: any) => f.name).sort()).toEqual(['@scope/pkg', 'org.apache:commons']);
    expect(sc.advisories[0].url).toBeNull();
    // A walker that does not use sourceLink: nothing outside `untrusted` holds markdown, markup or controls.
    const walk = (v: unknown, path: string, inUntrusted: boolean) => {
      if (typeof v === 'string') {
        if (inUntrusted) return;
        expect(v, path).not.toMatch(/\]\(|!\[|[<>]|\p{Cc}|\p{Cf}/u);
        if (/(^|\.)(url|sourceUrl)$/.test(path))
          expect(v, path).toMatch(/^https:\/\/[a-z0-9.-]+\/[A-Za-z0-9._~%/:@+-]*$/);
        else expect(v, path).not.toMatch(/https?:\/\//i);
      } else if (Array.isArray(v)) {
        for (const [i, x] of v.entries()) walk(x, `${path}[${i}]`, inUntrusted);
      } else if (v && typeof v === 'object')
        for (const [k, x] of Object.entries(v))
          walk(x, path ? `${path}.${k}` : k, inUntrusted || k === 'untrusted');
    };
    walk(sc, '', false);
    spy.restore();
  });

  it('check_packages shows only the caller’s own names and versions, never ti-api’s', async () => {
    const spy = mockJwks([key]);
    const body = F.checkBody(2) as any;
    body.results[0].package = { ecosystem: 'npm', name: 'left-pad', version: '1.0.0' };
    body.results.push({
      ...body.results[0],
      package: { ecosystem: 'npm', name: 'x](https://evil.test)', version: '1.0.0' },
    });
    body.noRecord.push({ ecosystem: 'npm', name: 'invented', version: '9.9.9' });
    const api = fakeApi(() => ok(body));
    const token = await signJwt(key);
    const c = modernCall(token, 'tools/call', {
      name: 'mti_check_packages',
      arguments: { packages: [{ ecosystem: 'npm', name: 'Left-Pad', version: '1.0.0' }] },
    });
    const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api));
    const sc = (await bodyOf(res)).result.structuredContent;
    expect(sc.results.map((r: any) => r.package)).toEqual([
      { ecosystem: 'npm', name: 'left-pad', version: '1.0.0' },
    ]);
    expect(JSON.stringify(sc)).not.toContain('invented');
    expect(JSON.stringify(sc)).not.toContain('evil.test');
    spy.restore();
  });

  it('a cursor made for one user does not open for another', async () => {
    const spy = mockJwks([key]);
    const api = fakeApi(() => ok({ ...F.searchBody, cursor: 'abc_DEF' }));
    const env = withApi(BASE_ENV, api);
    const args = { query: 'a' };
    const t1 = await signJwt(key);
    const c1 = modernCall(t1, 'tools/call', { name: 'mti_search', arguments: args });
    const first = await bodyOf(await send({ headers: c1.headers, body: c1.body }, env));
    const cursor = first.result.structuredContent.nextCursor as string;
    expect(cursor).toBeTruthy();
    const t2 = await signJwt(key, goodPayload({ sub: 'user_2zzzzzzzzzzz' }));
    const before = api.calls.length;
    const c2 = modernCall(t2, 'tools/call', { name: 'mti_search', arguments: { ...args, cursor } });
    const other = await bodyOf(await send({ headers: c2.headers, body: c2.body }, env));
    expect(other.error.code).toBe(-32602);
    expect(api.calls.length).toBe(before);
    const c3 = modernCall(t1, 'tools/call', { name: 'mti_search', arguments: { ...args, cursor } });
    expect(
      (await bodyOf(await send({ headers: c3.headers, body: c3.body }, env))).result.isError,
    ).toBeFalsy();
    expect(SUB).not.toBe('user_2zzzzzzzzzzz');
    spy.restore();
  });
});

describe('cleaner and links, round 2', () => {
  it('loops until stable and keeps text next to a reference marker', () => {
    expect(clean('&#xFF1C;script&#xFF1E;hi', 100)).not.toMatch(/[<>]|script>/);
    expect(clean('https&#xFF1A;&#xFF0F;&#xFF0F;evil.test', 100)).not.toContain('evil.test');
    expect(clean('[CVE-2026-1]: overflow in foo', 100)).toContain('overflow in foo');
  });
  it('mtiLink refuses a ".." part', () => {
    expect(mtiLink({ MCP_RESOURCE_URL: 'https://mti.test/mcp' }, 'entry', '..')).toBeNull();
    expect(mtiLink({ MCP_RESOURCE_URL: 'https://mti.test/mcp' }, 'entry', 'a..b')).toBeNull();
    expect(mtiLink({ MCP_RESOURCE_URL: 'https://mti.test/mcp' }, 'entry', 'CVE-2026-1')).toBe(
      'https://mti.test/e/CVE-2026-1',
    );
  });
});
