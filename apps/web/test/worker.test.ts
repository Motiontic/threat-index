import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BASE_HEADERS } from '../app/lib/security.server';

const handle = vi.hoisted(() => vi.fn());

const cf = vi.hoisted(() => ({
  env: { TI_ENV: 'production', DATA_SOURCE: 'fixtures', API: {} } as Record<string, unknown>,
}));
vi.mock('cloudflare:workers', () => cf);
vi.mock('virtual:react-router/server-build', () => ({}));
vi.mock('react-router', () => ({ createRequestHandler: () => handle }));

import worker from '../workers/app';

const call = (req: Request) => (worker.fetch as (r: Request) => Promise<Response>)(req);

describe('Worker fetch handler', () => {
  beforeEach(() => handle.mockReset());

  const redirect = async () => {
    handle.mockResolvedValue(new Response(null, { status: 301, headers: { Location: '/e/CVE-2025-3248' } }));
    return call(new Request('https://example.test/e/cve-2025-3248'));
  };

  it('gives a redirect the document headers and a CSP nonce, with noindex in fixtures mode', async () => {
    Object.assign(cf.env, { TI_ENV: 'production', DATA_SOURCE: 'fixtures' });
    const res = await redirect();
    expect(res.status).toBe(301);
    expect(res.headers.get('Location')).toBe('/e/CVE-2025-3248');
    for (const name of Object.keys(BASE_HEADERS))
      expect(res.headers.get(name), name).toBe(BASE_HEADERS[name]);
    expect(res.headers.get('X-Robots-Tag')).toBe('noindex');
    expect(res.headers.get('Content-Security-Policy')).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=_-]+'/);
  });

  it('has no noindex on a redirect in api mode in production, but has it on staging', async () => {
    Object.assign(cf.env, { TI_ENV: 'production', DATA_SOURCE: 'api' });
    expect((await redirect()).headers.get('X-Robots-Tag')).toBeNull();
    Object.assign(cf.env, { TI_ENV: 'staging', DATA_SOURCE: 'api' });
    expect((await redirect()).headers.get('X-Robots-Tag')).toBe('noindex');
  });

  it('passes a document response through untouched', async () => {
    const doc = new Response('<html></html>', { status: 200 });
    handle.mockResolvedValue(doc);
    expect(await call(new Request('https://example.test/'))).toBe(doc);
  });
});

describe('workers.dev redirect', () => {
  const SITE = 'https://mti.motiontic.com';
  const prod = (extra: Record<string, unknown> = {}) =>
    Object.assign(cf.env, { TI_ENV: 'production', DATA_SOURCE: 'api', SITE_ORIGIN: SITE, ...extra });

  beforeEach(() => {
    handle.mockReset();
    handle.mockResolvedValue(new Response('<html></html>', { status: 200 }));
  });
  afterEach(() => {
    cf.env.SITE_ORIGIN = undefined;
  });

  it('sends a production page request on workers.dev to the same path on the site URL (301)', async () => {
    prod();
    const res = await call(new Request('https://ti-web.acct.workers.dev/e/CVE-2025-3248?x=1'));
    expect(res.status).toBe(301);
    expect(res.headers.get('Location')).toBe(`${SITE}/e/CVE-2025-3248?x=1`);
    expect(handle).not.toHaveBeenCalled();
  });

  it('does not redirect the site host, staging, a missing site URL, assets or non-GET requests', async () => {
    prod();
    expect((await call(new Request(`${SITE}/sources`))).status).toBe(200);
    expect((await call(new Request('https://ti-web.acct.workers.dev/assets/app.js'))).status).toBe(200);
    expect(
      (await call(new Request('https://ti-web.acct.workers.dev/account.data', { method: 'GET' }))).status,
    ).toBe(200);
    expect(
      (await call(new Request('https://ti-web.acct.workers.dev/search', { method: 'POST' }))).status,
    ).toBe(200);
    prod({ TI_ENV: 'staging' });
    expect((await call(new Request('https://ti-web-staging.acct.workers.dev/sources'))).status).toBe(200);
    prod({ SITE_ORIGIN: undefined });
    expect((await call(new Request('https://ti-web.acct.workers.dev/sources'))).status).toBe(200);
  });
});

describe('MCP forwarding', () => {
  const mcpFetch = vi.fn();
  const limit = vi.fn();
  const answer = () => new Response('{"from":"mcp"}', { status: 503, headers: { 'X-From': 'mcp' } });

  beforeEach(() => {
    handle.mockReset();
    handle.mockResolvedValue(new Response('<html></html>', { status: 200 }));
    mcpFetch.mockReset();
    mcpFetch.mockImplementation(async () => answer());
    limit.mockReset();
    limit.mockResolvedValue({ success: true });
    Object.assign(cf.env, {
      TI_ENV: 'production',
      DATA_SOURCE: 'api',
      MCP_ENABLED: '1',
      MCP: { fetch: mcpFetch },
      RL_PAGES: { limit },
    });
  });
  afterEach(() => {
    for (const k of ['MCP_ENABLED', 'MCP', 'RL_PAGES']) delete cf.env[k];
  });

  const forwarded = () => mcpFetch.mock.calls[0]?.[0] as Request;

  it.each([
    '/mcp',
    '/mcp/server-card',
    '/mcp/a/b',
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
  ])('forwards %s to ti-mcp and returns its response unchanged', async (path) => {
    const res = await call(new Request(`https://example.test${path}`, { method: 'POST', body: '{"a":1}' }));
    expect(mcpFetch).toHaveBeenCalledTimes(1);
    expect(handle).not.toHaveBeenCalled();
    expect(res.status).toBe(503);
    expect(res.headers.get('X-From')).toBe('mcp');
    expect(await res.text()).toBe('{"from":"mcp"}');
    // No page headers, no noindex logic: ti-mcp sets its own.
    expect(res.headers.get('X-Robots-Tag')).toBeNull();
    expect(res.headers.get('Content-Security-Policy')).toBeNull();
    expect(res.headers.get('Strict-Transport-Security')).toBeNull();
    expect(new URL(forwarded().url).pathname).toBe(path);
    expect(forwarded().method).toBe('POST');
    expect(await forwarded().text()).toBe('{"a":1}');
  });

  it('keeps the query string and other headers, but removes the cookie', async () => {
    await call(
      new Request('https://example.test/mcp?x=1', {
        method: 'POST',
        headers: { Cookie: '__session=secret', Authorization: 'Bearer t', 'Content-Type': 'application/json' },
      }),
    );
    const req = forwarded();
    expect(new URL(req.url).search).toBe('?x=1');
    expect(req.headers.has('cookie')).toBe(false);
    expect(req.headers.get('authorization')).toBe('Bearer t');
    expect(req.headers.get('content-type')).toBe('application/json');
  });

  it('removes every incoming x-ti-mcp-* header, whatever its case', async () => {
    await call(
      new Request('https://example.test/mcp', {
        method: 'POST',
        headers: {
          'x-ti-mcp-sub': 'user_2abcdefghijk',
          'X-TI-MCP-Scopes': 'mti:read mti:watch',
          'x-ti-mcp-client': 'c',
          'x-ti-mcp-ts': '1',
          'x-ti-mcp-sig': 'deadbeef',
          'x-ti-mcp-anything': 'x',
          'x-ti-other': 'kept',
        },
      }),
    );
    const names = [...forwarded().headers.keys()];
    expect(names.filter((n) => n.startsWith('x-ti-mcp-'))).toEqual([]);
    expect(forwarded().headers.get('x-ti-other')).toBe('kept');
  });

  it('answers 404 JSON with the base security headers when MCP is off, and never calls ti-mcp', async () => {
    for (const off of ['0', undefined, '', 'true']) {
      cf.env.MCP_ENABLED = off;
      const res = await call(new Request('https://example.test/mcp', { method: 'POST' }));
      expect(res.status, String(off)).toBe(404);
      expect(res.headers.get('Content-Type')).toContain('application/json');
      expect(await res.json()).toEqual({ error: 'not_found' });
      for (const name of ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy'])
        expect(res.headers.get(name), name).toBe(BASE_HEADERS[name]);
      expect(res.headers.get('Cache-Control')).toBe('no-store');
    }
    cf.env.MCP_ENABLED = '0';
    for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'])
      expect((await call(new Request(`https://example.test${path}`))).status, path).toBe(404);
    expect(mcpFetch).not.toHaveBeenCalled();
    expect(handle).not.toHaveBeenCalled();
  });

  it('answers 404 (not a crash) when the MCP binding is missing, even if switched on', async () => {
    delete cf.env.MCP;
    expect((await call(new Request('https://example.test/mcp'))).status).toBe(404);
  });

  it.each(['/mcpx', '/mcp-docs', '/mcp.txt', '/MCP', '/x/mcp', '/.well-known/oauth-protected-resourcex', '/.well-known/security.txt'])(
    'does not forward %s: it is a page',
    async (path) => {
      const res = await call(new Request(`https://example.test${path}`));
      expect(mcpFetch).not.toHaveBeenCalled();
      expect(handle).toHaveBeenCalledTimes(1);
      expect(res.status).toBe(200);
    },
  );

  it('the page limiter does not count forwarded calls, and still counts pages', async () => {
    cf.env.RL_PAGES = { limit };
    for (let i = 0; i < 3; i++)
      await call(new Request('https://example.test/mcp', { method: 'POST', headers: { 'cf-connecting-ip': '203.0.113.7' } }));
    expect(limit).not.toHaveBeenCalled();
    await call(new Request('https://example.test/sources', { headers: { 'cf-connecting-ip': '203.0.113.7' } }));
    expect(limit).toHaveBeenCalledTimes(1);
  });

  it('forwards even when the page limiter would refuse the visitor', async () => {
    limit.mockResolvedValue({ success: false });
    const res = await call(new Request('https://example.test/mcp', { method: 'POST', headers: { 'cf-connecting-ip': '203.0.113.7' } }));
    expect(res.status).toBe(503);
    expect(mcpFetch).toHaveBeenCalledTimes(1);
  });

  it('forwards before the workers.dev redirect', async () => {
    Object.assign(cf.env, { SITE_ORIGIN: 'https://mti.motiontic.com' });
    const res = await call(new Request('https://ti-web.acct.workers.dev/mcp', { method: 'POST' }));
    cf.env.SITE_ORIGIN = undefined;
    expect(res.status).toBe(503);
    expect(mcpFetch).toHaveBeenCalledTimes(1);
  });
});
