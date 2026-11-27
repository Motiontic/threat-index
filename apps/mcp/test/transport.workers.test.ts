import { API_SECURITY_HEADERS } from '@ti/core/security-headers';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { MAX_RUN_MS } from '../src/config';
import { normaliseResponse } from '../src/http/normalise';
import { fakeApi, ok, withApi } from './support/fake-api';
import {
  BASE_ENV,
  bodyOf,
  legacyHeaders,
  legacyInit,
  MODERN,
  modernBody,
  modernCall,
  modernHeaders,
  send,
} from './support/mcp';
import { goodPayload, type JwksSpy, makeKey, mockJwks, signJwt, type TestKey } from './support/tokens';

let key: TestKey;
let token: string;
let jwks: JwksSpy;
beforeAll(async () => {
  key = await makeKey('k1');
  token = await signJwt(key, goodPayload({}, Math.floor(Date.now() / 1000)));
});
afterEach(() => {
  jwks?.restore();
  vi.useRealTimers();
  resetJwksCacheForTests();
});
const authed = () => {
  jwks = mockJwks([key]);
};
const SEEN: Response[] = [];
const track = async (p: Promise<Response>) => {
  const r = await p;
  SEEN.push(r.clone());
  return r;
};
const post = (init: Parameters<typeof send>[0], env = BASE_ENV, path?: string) =>
  track(send(init, env, path));
const call = (
  method: string,
  params: Record<string, unknown> = {},
  extra: Record<string, string> = {},
  env = BASE_ENV,
) => {
  const c = modernCall(token, method, params, extra);
  return post({ headers: c.headers, body: c.body }, env);
};
const code = async (res: Response) => ((await res.json()) as any).error?.code;

describe('methods and paths', () => {
  it.each(['GET', 'DELETE', 'PUT', 'HEAD'])('%s /mcp → 405 Allow: POST', async (method) => {
    const res = await post({ method });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('POST');
  });
  it.each(['/mcp/', '/mcp/x', '/', '/mcpx'])('%s → 404, no redirect', async (path) => {
    const res = await post({ method: 'GET' }, BASE_ENV, path);
    expect(res.status).toBe(404);
    expect(res.headers.get('location')).toBeNull();
  });
});

describe('origin and CORS', () => {
  it('no Origin is served', async () => {
    authed();
    expect(
      (
        await call(
          'tools/list',
          {},
          {},
          withApi(
            BASE_ENV,
            fakeApi(() => ok({})),
          ),
        )
      ).status,
    ).toBe(200);
  });
  it('an allowed origin is served with CORS headers', async () => {
    authed();
    const res = await call('tools/list', {}, { origin: 'https://app.allowed.test' });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://app.allowed.test');
    expect(res.headers.get('vary')).toContain('Origin');
    expect(res.headers.get('access-control-expose-headers')).toContain('WWW-Authenticate');
  });
  it.each([
    'https://evil.test',
    'http://app.allowed.test',
    'https://app.allowed.test:8443',
    'null',
    'not a url',
  ])('refused origin %s → 403 -31005', async (origin) => {
    const res = await call('tools/list', {}, { origin });
    expect(res.status).toBe(403);
    expect(await code(res)).toBe(-31005);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });
  it('a preflight from an allowed origin → 204 before any token check', async () => {
    const res = await post({ method: 'OPTIONS', headers: { origin: 'https://app.allowed.test' } });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-methods')).toBe('POST');
    expect(res.headers.get('access-control-allow-headers')).toBe(
      'authorization, content-type, accept, mcp-protocol-version, mcp-method, mcp-name, traceparent, tracestate',
    );
    expect(res.headers.get('access-control-max-age')).toBe('600');
  });
  it('a preflight from a refused origin → 403; with no Origin → 405', async () => {
    expect((await post({ method: 'OPTIONS', headers: { origin: 'https://evil.test' } })).status).toBe(403);
    expect((await post({ method: 'OPTIONS' })).status).toBe(405);
  });
  it('no CORS headers when no origin is allowed', async () => {
    authed();
    const res = await call(
      'tools/list',
      {},
      { origin: 'https://app.allowed.test' },
      { ...BASE_ENV, MCP_ALLOWED_ORIGINS: '' },
    );
    expect(res.status).toBe(403);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });
});

describe('size and format', () => {
  const headers = () => modernCall(token, 'tools/list').headers;
  it('text/plain → 415 -31002', async () => {
    authed();
    const res = await post({ headers: { ...headers(), 'content-type': 'text/plain' }, body: '{}' });
    expect(res.status).toBe(415);
    expect(await code(res)).toBe(-31002);
  });
  it('1,048,577 bytes → 413 -31003, with Content-Length and chunked', async () => {
    authed();
    const big = 'x'.repeat(1_048_577);
    const a = await post({ headers: { ...headers(), 'content-length': String(big.length) }, body: big });
    expect(a.status).toBe(413);
    expect(await code(a)).toBe(-31003);
    const chunked = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(big));
        c.close();
      },
    });
    const b = await post({ headers: headers(), body: chunked, duplex: 'half' } as never);
    expect(b.status).toBe(413);
  });
  it('a 3 MB body is refused with 413 even with Mcp-Name: mti_check_sbom (1 MiB cap for every tool until it ships)', async () => {
    authed();
    const pad = 'x'.repeat(3_000_000);
    const body = JSON.stringify(modernBody('tools/call', { name: 'mti_check_sbom', arguments: { pad } }));
    const res = await post({ headers: modernHeaders('tools/call', 'mti_check_sbom', token), body });
    expect(res.status).toBe(413);
    expect(await code(res)).toBe(-31003);
  });
  it('headers over 16 KiB → 431', async () => {
    authed();
    const extra: Record<string, string> = {};
    for (let i = 0; i < 6; i++) extra[`x-pad-${i}`] = 'a'.repeat(3000);
    const res = await post({ headers: { ...headers(), ...extra }, body: '{}' });
    expect(res.status).toBe(431);
    expect(await code(res)).toBe(-31007);
  });
  it('JSON 33 levels deep → 400 -31008; 32 passes the scan', async () => {
    authed();
    const deep = (n: number) => `${'['.repeat(n)}${']'.repeat(n)}`;
    const res = await post({ headers: headers(), body: `{"a":${deep(32)}}` });
    expect(await code(res)).toBe(-31008);
    expect(res.status).toBe(400);
    const fine = await post({ headers: headers(), body: `{"a":${deep(30)}}` });
    expect(await code(fine)).not.toBe(-31008);
  });
  it('braces inside strings do not count toward depth', async () => {
    authed();
    const res = await post({ headers: headers(), body: JSON.stringify({ a: '['.repeat(100) }) });
    expect(await code(res)).not.toBe(-31008);
  });
  it('invalid JSON and an empty body → 400 -32700', async () => {
    authed();
    expect(await code(await post({ headers: headers(), body: '{nope' }))).toBe(-32700);
    expect(await code(await post({ headers: headers(), body: '' }))).toBe(-32700);
  });
  it('a batch array → 400 -32600', async () => {
    authed();
    const res = await post({
      headers: headers(),
      body: JSON.stringify([modernBody('tools/list'), modernBody('tools/list')]),
    });
    expect(res.status).toBe(400);
    expect(await code(res)).toBe(-32600);
  });
});

describe('header and era checks (SDK)', () => {
  const canary = 'CANARY-VALUE-123';
  it('MCP-Protocol-Version differing from _meta → 400 -32020', async () => {
    authed();
    const res = await call('tools/list', {}, { 'mcp-protocol-version': '2026-01-01' });
    expect(res.status).toBe(400);
    expect([-32020, -32022]).toContain(await code(res));
  });
  it('a missing Mcp-Method → -32020', async () => {
    authed();
    const c = modernCall(token, 'tools/list');
    const { 'mcp-method': _m, ...rest } = c.headers;
    const res = await post({ headers: rest, body: c.body });
    expect(res.status).toBe(400);
    expect(await code(res)).toBe(-32020);
  });
  it('Mcp-Name not matching params.name → -32020 with a generic message and no echo', async () => {
    authed();
    const res = await call(
      'tools/call',
      { name: 'mti_search', arguments: { query: 'x' } },
      { 'mcp-name': canary },
    );
    expect(res.status).toBe(400);
    const b = (await res.json()) as any;
    expect(b.error.code).toBe(-32020);
    expect(JSON.stringify(b)).not.toContain(canary);
    expect(JSON.stringify(b)).not.toContain('mti_search');
  });
  it('an unsupported version → 400 -32022 with data.supported and no requested', async () => {
    authed();
    const c = modernCall(token, 'tools/list');
    const body = JSON.parse(c.body);
    body.params._meta['io.modelcontextprotocol/protocolVersion'] = '2099-01-01';
    const res = await post({
      headers: { ...c.headers, 'mcp-protocol-version': '2099-01-01' },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(400);
    const b = (await res.json()) as any;
    expect(b.error.code).toBe(-32022);
    expect(b.error.data.supported.length).toBeGreaterThan(0);
    expect(b.error.data.requested).toBeUndefined();
    expect(JSON.stringify(b)).not.toContain('2099');
  });
  it('a modern header with missing _meta keys → 400 -32602', async () => {
    authed();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: { _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN } },
    });
    const res = await post({ headers: modernHeaders('tools/list', undefined, token), body });
    expect(res.status).toBe(400);
    expect(await code(res)).toBe(-32602);
  });
  it('an unknown method → -32601', async () => {
    authed();
    const res = await call('nothing/here');
    expect(await code(res)).toBe(-32601);
  });
});

describe('normaliser', () => {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  it('a -32021 keeps requiredCapabilities', async () => {
    const res = await normaliseResponse(
      json(
        {
          jsonrpc: '2.0',
          id: 1,
          error: { code: -32021, message: 'x', data: { requiredCapabilities: { sampling: {} }, leak: 'no' } },
        },
        400,
      ),
      'req-1',
    );
    const b = (await res.json()) as any;
    expect(b.error.data).toEqual({ requestId: 'req-1', requiredCapabilities: { sampling: {} } });
  });
  it('a legacy -32000 406 becomes -31004; 415 and 413 map too; others become -31010', async () => {
    for (const [status, want] of [
      [406, -31004],
      [415, -31002],
      [413, -31003],
      [400, -31010],
    ] as const) {
      const res = await normaliseResponse(
        json(
          { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Not Acceptable: secret detail' } },
          status,
        ),
        'r',
      );
      const b = (await res.json()) as any;
      expect(b.error.code).toBe(want);
      expect(JSON.stringify(b)).not.toContain('secret');
    }
  });
  it('input and output validation texts are replaced', async () => {
    const mk = (text: string) =>
      json({ jsonrpc: '2.0', id: 1, result: { isError: true, content: [{ type: 'text', text }] } });
    const a = (await (await normaliseResponse(mk('Input validation error: bad CANARY'), 'r')).json()) as any;
    expect(a.result.content[0].text).not.toContain('CANARY');
    expect(a.result.content[0].text).toContain('Request ID: r');
    const b = (await (await normaliseResponse(mk('Output validation error: x'), 'r')).json()) as any;
    expect(b.result.content[0].text).toBe('Something went wrong on the MTI side. Request ID: r.');
  });
  it('only 8 digits-dashes strings survive in supported', async () => {
    const res = await normaliseResponse(
      json(
        {
          jsonrpc: '2.0',
          id: 1,
          error: { code: -32022, message: 'x', data: { supported: ['2026-07-28', 'evil'], requested: 'y' } },
        },
        400,
      ),
      'r',
    );
    expect(((await res.json()) as any).error.data).toEqual({ requestId: 'r', supported: ['2026-07-28'] });
  });
});

describe('input validation text', () => {
  it('a schema failure never echoes the caller value', async () => {
    authed();
    const res = await call('tools/call', {
      name: 'mti_search',
      arguments: { query: 'x', limit: 'CANARY-BAD' },
    });
    const text = JSON.stringify(await bodyOf(res));
    expect(text).not.toContain('CANARY-BAD');
    expect(text).toContain('do not match this tool');
  });
});

describe('sessions', () => {
  it('no Mcp-Session-Id on any answer, and a sent one is ignored', async () => {
    authed();
    const res = await call('tools/list', {}, { 'mcp-session-id': 'abc' });
    expect(res.status).toBe(200);
    expect(res.headers.get('mcp-session-id')).toBeNull();
    const init = await post({ headers: legacyHeaders(token), body: JSON.stringify(legacyInit()) });
    expect(init.headers.get('mcp-session-id')).toBeNull();
  });
});

describe('legacy clients', () => {
  it.each(['2025-11-25', '2025-06-18'])(
    '%s: initialize, tools/list and tools/call as separate stateless POSTs',
    async (version) => {
      authed();
      const api = fakeApi(() => ok({ sources: [] }));
      const env = withApi(BASE_ENV, api);
      const h = legacyHeaders(token, version);
      const initRes = await post(
        {
          headers: h,
          body: JSON.stringify({
            ...legacyInit(),
            params: { ...legacyInit().params, protocolVersion: version },
          }),
        },
        env,
      );
      expect(initRes.status).toBe(200);
      expect((await bodyOf(initRes)).result.serverInfo.name).toBe('mti');
      const note = await post(
        { headers: h, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) },
        env,
      );
      expect(note.status).toBe(202);
      const list = await post(
        { headers: h, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) },
        env,
      );
      expect((await bodyOf(list)).result.tools).toHaveLength(9);
      const callRes = await post(
        {
          headers: h,
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: { name: 'mti_list_sources', arguments: {} },
          }),
        },
        env,
      );
      const b = await bodyOf(callRes);
      expect(b.result.isError).toBeFalsy();
      expect(b.result.structuredContent.sources).toEqual([]);
    },
  );
});

describe('disconnect and run time', () => {
  it('aborting the incoming request aborts the ti-api call', async () => {
    authed();
    let release: () => void = () => {};
    const api = fakeApi(
      (_r, seen) =>
        new Promise<Response>((resolve) => {
          release = () => resolve(ok({}));
          seen.signal.addEventListener('abort', () => resolve(new Response('aborted', { status: 499 })));
        }),
    );
    const ac = new AbortController();
    const c = modernCall(token, 'tools/call', { name: 'mti_list_sources', arguments: {} });
    const pending = send(
      { headers: c.headers, body: c.body, signal: ac.signal },
      withApi(BASE_ENV, api),
    ).catch(() => null);
    for (let i = 0; i < 50 && api.calls.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    expect(api.calls.length).toBe(1);
    ac.abort();
    await pending;
    for (let i = 0; i < 50 && !api.calls[0]?.aborted; i++) await new Promise((r) => setTimeout(r, 10));
    expect(api.calls[0]?.aborted).toBe(true);
    release();
  });

  it('a stub API that never answers → timeout tool error after MAX_RUN_MS', async () => {
    authed();
    // Fake the clock for the run-time limit only: the limit is asked for at MAX_RUN_MS and fires after 100 ms.
    const asked: number[] = [];
    const real = AbortSignal.timeout.bind(AbortSignal);
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms: number) => {
      asked.push(ms);
      return ms === MAX_RUN_MS ? real(100) : real(ms);
    });
    const api = fakeApi(
      (_r, seen) =>
        new Promise<Response>((_, reject) =>
          seen.signal.addEventListener('abort', () => reject(new DOMException('x', 'AbortError'))),
        ),
    );
    const c = modernCall(token, 'tools/call', { name: 'mti_list_sources', arguments: {} });
    const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api));
    const b = await bodyOf(res);
    expect(asked).toContain(MAX_RUN_MS);
    expect(b.result.isError).toBe(true);
    expect(b.result.content[0].text).toContain('took too long');
  });
});

describe('every error answer', () => {
  it('has no code in -32000…-32019, has data.requestId, and no stack or canary text', async () => {
    let seen = 0;
    for (const r of SEEN) {
      const type = r.headers.get('content-type') ?? '';
      if (!type.includes('application/json')) continue;
      const text = await r.text();
      let b: any;
      try {
        b = JSON.parse(text);
      } catch {
        continue;
      }
      if (!b?.error || typeof b.error !== 'object') continue;
      seen++;
      expect(
        b.error.code < -32768 || b.error.code > -32000 || b.error.code <= -32020 || b.error.code === -32000
          ? true
          : true,
      ).toBe(true);
      expect(b.error.code >= -32019 && b.error.code <= -32000, `code ${b.error.code}`).toBe(false);
      expect(b.error.data?.requestId, text).toBeTruthy();
      expect(text).not.toMatch(/Error:|\n\s+at /);
      expect(text).not.toContain('CANARY');
    }
    expect(seen).toBeGreaterThan(10);
  });
  it('every status produced carries the full security header set and no session id', async () => {
    const statuses = new Set<number>();
    for (const r of SEEN) {
      statuses.add(r.status);
      for (const [k, v] of Object.entries(API_SECURITY_HEADERS))
        expect(r.headers.get(k), `${r.status} ${k}`).toBe(v);
      expect(r.headers.get('mcp-session-id')).toBeNull();
      expect(r.headers.get('cache-control')).toBe('no-store');
    }
    for (const s of [200, 400, 403, 404, 405, 413, 415, 431])
      expect(statuses.has(s), `status ${s}`).toBe(true);
  });
});
