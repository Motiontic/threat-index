import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { bearerFrom } from '../src/auth/token';
import { fakeApi, ok, withApi } from './support/fake-api';
import { BASE_ENV, bodyOf, MODERN, modernCall, send } from './support/mcp';
import {
  b64u,
  goodPayload,
  ISS,
  JWKS_URL,
  makeKey,
  mockJwks,
  RES,
  signJwt,
  type TestKey,
} from './support/tokens';

let key: TestKey;
let other: TestKey;
beforeAll(async () => {
  key = await makeKey('k1');
  other = await makeKey('k1'); // same kid, different key: a bad signature
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  resetJwksCacheForTests();
});

const list = (token: string | undefined, extra: Record<string, string> = {}, env = BASE_ENV) => {
  const c = modernCall(token, 'tools/list', {}, extra);
  return send({ headers: c.headers, body: c.body }, env);
};
const WWW = (res: Response) => res.headers.get('www-authenticate') ?? '';

describe('bearerFrom', () => {
  const req = (h?: string) =>
    new Request('https://x.test/', { headers: h === undefined ? {} : { authorization: h } });
  it('reads only a Bearer header', () => {
    expect(bearerFrom(req())).toEqual({ kind: 'none' });
    expect(bearerFrom(req('Basic abc'))).toEqual({ kind: 'none' });
    expect(bearerFrom(req('bearer abc.def'))).toEqual({ kind: 'token', token: 'abc.def' });
    expect(bearerFrom(req('Bearer'))).toEqual({ kind: 'malformed' });
    expect(bearerFrom(req('Bearer a b'))).toEqual({ kind: 'malformed' });
    expect(bearerFrom(req('Bearer a, Bearer b'))).toEqual({ kind: 'malformed' });
    expect(bearerFrom(req('Bearer a$b'))).toEqual({ kind: 'malformed' });
    expect(bearerFrom(req(`Bearer ${'a'.repeat(8193)}`))).toEqual({ kind: 'malformed' });
  });
});

describe('token matrix', () => {
  it('a good token is served', async () => {
    const spy = mockJwks([key]);
    const api = fakeApi(() => ok({}));
    const res = await list(await signJwt(key), {}, withApi(BASE_ENV, api));
    expect(res.status).toBe(200);
    const body = await bodyOf(res);
    expect(body.result.tools).toHaveLength(9);
    spy.restore();
  });

  const bad: [string, () => Promise<string>][] = [
    ['typ JWT', () => signJwt(key, goodPayload(), { typ: 'JWT' })],
    [
      'alg none',
      async () =>
        `${b64u(JSON.stringify({ alg: 'none', typ: 'at+jwt', kid: 'k1' }))}.${b64u(JSON.stringify(goodPayload()))}.${b64u('x')}`,
    ],
    [
      'HS256 signed with the public key bytes',
      async () => {
        const mac = await crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(String(key.publicJwk.n)),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign'],
        );
        const signing = `${b64u(JSON.stringify({ alg: 'HS256', typ: 'at+jwt', kid: 'k1' }))}.${b64u(JSON.stringify(goodPayload()))}`;
        return `${signing}.${b64u(await crypto.subtle.sign('HMAC', mac, new TextEncoder().encode(signing)))}`;
      },
    ],
    ['wrong iss', () => signJwt(key, goodPayload({ iss: 'https://evil.test' }))],
    ['iss with trailing slash', () => signJwt(key, goodPayload({ iss: `${ISS}/` }))],
    ['wrong aud', () => signJwt(key, goodPayload({ aud: 'https://mti.test/other' }))],
    ['aud with trailing slash', () => signJwt(key, goodPayload({ aud: `${RES}/` }))],
    [
      'aud array without the URL',
      () => signJwt(key, goodPayload({ aud: ['https://a.test', 'https://b.test'] })),
    ],
    ['expired by 6 s', () => signJwt(key, goodPayload({ exp: Math.floor(Date.now() / 1000) - 6 }))],
    ['nbf 60 s ahead', () => signJwt(key, goodPayload({ nbf: Math.floor(Date.now() / 1000) + 60 }))],
    ['iat in the future', () => signJwt(key, goodPayload({ iat: Math.floor(Date.now() / 1000) + 60 }))],
    [
      'lifetime over 7 days',
      () => signJwt(key, goodPayload({ exp: Math.floor(Date.now() / 1000) + 8 * 86400 })),
    ],
    ['missing client_id', () => signJwt(key, goodPayload({ client_id: undefined }))],
    ['machine subject', () => signJwt(key, goodPayload({ sub: 'mch_2abcdefghijk' }))],
    [
      'session token shape',
      () =>
        signJwt(key, goodPayload({ client_id: undefined, sid: 'sess_1', azp: 'https://app.test' }), {
          typ: 'JWT',
        }),
    ],
    ['ID token shape', () => signJwt(key, goodPayload({ aud: 'client-abc', nonce: 'n' }), { typ: 'JWT' })],
    ['opaque oat_', async () => 'oat_abcdefghijklmnop'],
    ['unknown kid', () => signJwt({ ...key, kid: 'nope' })],
    ['bad signature', () => signJwt({ ...other, kid: 'k1' })],
    ['crit header', () => signJwt(key, goodPayload(), { crit: ['x'] })],
  ];
  it.each(bad)('%s → 401 invalid_token', async (_name, make) => {
    const spy = mockJwks([key]);
    const res = await list(await make());
    expect(res.status).toBe(401);
    expect(WWW(res)).toContain('error="invalid_token"');
    expect(WWW(res)).toContain(
      `resource_metadata="https://mti.test/.well-known/oauth-protected-resource/mcp"`,
    );
    expect(WWW(res)).toContain('scope="mti:read"');
    expect(((await res.json()) as { error: string }).error).toBe('invalid_token');
    spy.restore();
  });

  it('a jku header pointing elsewhere is ignored and never fetched', async () => {
    const spy = mockJwks([key]);
    const api = fakeApi(() => ok({}));
    const res = await list(
      await signJwt(key, goodPayload(), {
        jku: 'https://evil.test/jwks.json',
        x5u: 'https://evil.test/x',
        jwk: {},
      }),
      {},
      withApi(BASE_ENV, api),
    );
    expect(res.status).toBe(200);
    expect(spy.calls).toEqual([JWKS_URL]);
    spy.restore();
  });

  it('two Authorization values and over 8,192 characters → 401 invalid_token', async () => {
    const spy = mockJwks([key]);
    const t = await signJwt(key);
    const two = await list(undefined, { authorization: `Bearer ${t}, Bearer ${t}` });
    expect(two.status).toBe(401);
    expect(WWW(two)).toContain('invalid_token');
    // A header value over 8,192 bytes is refused earlier still (step 3, 431), so a token over 8,192
    // characters never reaches the token check through the pipeline; bearerFrom has its own unit case above.
    const long = await list(undefined, { authorization: `Bearer ${'a'.repeat(8200)}` });
    expect(long.status).toBe(431);
    const justUnder = await list(undefined, { authorization: `Bearer ${'a'.repeat(8100)}` });
    expect(justUnder.status).toBe(401);
    expect(WWW(justUnder)).toContain('invalid_token');
    spy.restore();
  });

  it('a token anywhere but the header → 401 with no error attribute, and the body is never read', async () => {
    const spy = mockJwks([key]);
    const t = await signJwt(key);
    const c = modernCall(undefined, 'tools/list');
    const cases: [string, RequestInit & { url?: string }][] = [
      ['query', { headers: c.headers, body: c.body }],
      ['cookie', { headers: { ...c.headers, cookie: `__session=${t}` }, body: c.body }],
      ['body', { headers: c.headers, body: JSON.stringify({ ...JSON.parse(c.body), access_token: t }) }],
      ['basic', { headers: { ...c.headers, authorization: `Basic ${btoa('a:b')}` }, body: c.body }],
    ];
    for (const [name, init] of cases) {
      const res = await send(init as never, BASE_ENV, name === 'query' ? `/mcp?access_token=${t}` : '/mcp');
      expect(res.status, name).toBe(401);
      expect(WWW(res), name).not.toContain('error=');
      expect(WWW(res), name).toContain('resource_metadata=');
    }
    expect(spy.calls).toEqual([]);
    spy.restore();
  });

  it('no token: the body is never read or checked', async () => {
    const headers = modernCall(undefined, 'tools/list').headers;
    const junk = await send({ headers, body: '{not json' });
    expect(junk.status).toBe(401);
    const huge = await send({ headers, body: 'x'.repeat(2_000_000) });
    expect(huge.status).toBe(401);
    const wrongType = await send({ headers: { ...headers, 'content-type': 'text/plain' }, body: '{}' });
    expect(wrongType.status).toBe(401);
  });
});

describe('scopes', () => {
  it('mti:watch alone → 403 insufficient_scope naming mti:read', async () => {
    const spy = mockJwks([key]);
    const res = await list(await signJwt(key, goodPayload({ scope: 'mti:watch' })));
    expect(res.status).toBe(403);
    expect(WWW(res)).toContain('error="insufficient_scope"');
    expect(WWW(res)).toContain('scope="mti:read"');
    spy.restore();
  });

  it('unknown scopes are dropped from the assertion ti-api receives', async () => {
    const spy = mockJwks([key]);
    const api = fakeApi(() => ok({ sources: [] }));
    const t = await signJwt(key, goodPayload({ scope: 'offline_access mti:read admin mti:read' }));
    const c = modernCall(t, 'tools/call', { name: 'mti_list_sources', arguments: {} });
    const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api));
    expect(res.status).toBe(200);
    expect(api.calls[0]?.headers['x-ti-mcp-scopes']).toBe('mti:read');
    expect(api.calls[0]?.headers['x-ti-mcp-sub']).toBe('user_2abcdefghijk');
    expect(api.calls[0]?.headers.authorization).toBeUndefined();
    spy.restore();
  });
});

describe('keys', () => {
  it.each(['500', 'timeout', 'redirect', 'badjson', 'weak'] as const)(
    'JWKS %s with no cache → 503 with Retry-After and no challenge',
    async (mode) => {
      const spy = mockJwks([key], mode);
      const res = await list(await signJwt(key, goodPayload(), {}));
      expect(res.status).toBe(503);
      expect(res.headers.get('retry-after')).toBe('30');
      expect(res.headers.get('www-authenticate')).toBeNull();
      spy.restore();
    },
  );

  it('keys are cached: two requests make one fetch', async () => {
    const spy = mockJwks([key]);
    const api = fakeApi(() => ok({}));
    const t = await signJwt(key);
    await list(t, {}, withApi(BASE_ENV, api));
    await list(t, {}, withApi(BASE_ENV, api));
    expect(spy.calls).toEqual([JWKS_URL]);
    spy.restore();
  });

  it('an unknown kid refreshes at most once per 30 s', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-11-26T10:00:00Z'));
    const spy = mockJwks([key]);
    const stranger = await makeKey('zzz');
    const mk = () => signJwt(stranger, goodPayload({}, Math.floor(Date.now() / 1000)));
    expect((await list(await mk())).status).toBe(401);
    expect((await list(await mk())).status).toBe(401);
    expect((await list(await mk())).status).toBe(401);
    expect(spy.calls.length).toBe(1);
    vi.setSystemTime(new Date('2026-11-26T10:00:31Z'));
    expect((await list(await mk())).status).toBe(401);
    expect(spy.calls.length).toBe(2);
    spy.restore();
  });

  it("the JWKS URL is only ever the issuer's", async () => {
    const spy = mockJwks([key]);
    await list(await signJwt(key, goodPayload(), { kid: 'k1', jku: 'https://evil.test/x' }));
    await list(await signJwt({ ...key, kid: '../../etc' }));
    for (const u of spy.calls) expect(u).toBe(JWKS_URL);
    spy.restore();
  });
});

describe('metadata', () => {
  it('is exactly the four fields, with a path-aware URL only', async () => {
    const res = await send({ method: 'GET' }, BASE_ENV, '/.well-known/oauth-protected-resource/mcp');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
    expect(await res.json()).toEqual({
      resource: RES,
      authorization_servers: [ISS],
      scopes_supported: ['mti:read', 'mti:watch'],
      bearer_methods_supported: ['header'],
    });
    expect((await send({ method: 'GET' }, BASE_ENV, '/.well-known/oauth-protected-resource')).status).toBe(
      404,
    );
    expect(
      (await send({ method: 'POST' }, BASE_ENV, '/.well-known/oauth-protected-resource/mcp')).headers.get(
        'allow',
      ),
    ).toBe('GET, HEAD');
    expect(
      (await send({ method: 'HEAD' }, BASE_ENV, '/.well-known/oauth-protected-resource/mcp')).status,
    ).toBe(200);
  });
  it('gives CORS only to allowed origins', async () => {
    const yes = await send(
      { method: 'GET', headers: { origin: 'https://app.allowed.test' } },
      BASE_ENV,
      '/.well-known/oauth-protected-resource/mcp',
    );
    expect(yes.headers.get('access-control-allow-origin')).toBe('https://app.allowed.test');
    const no = await send(
      { method: 'GET', headers: { origin: 'https://evil.test' } },
      BASE_ENV,
      '/.well-known/oauth-protected-resource/mcp',
    );
    expect(no.headers.get('access-control-allow-origin')).toBeNull();
    const pre = await send(
      { method: 'OPTIONS', headers: { origin: 'https://app.allowed.test' } },
      BASE_ENV,
      '/.well-known/oauth-protected-resource/mcp',
    );
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-methods')).toBe('GET');
  });
});
void MODERN;
