import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs script without types
import { runSmoke } from '../scripts/smoke-staging.mjs';

const GOOD = {
  'x-request-id': 'req-12345678',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=()',
};
const STATUS: Record<string, number> = {
  '/v1/me': 401,
  '/v1/admin/ops': 403,
  '/ops': 404,
  '/mcp': 405,
  '/no-such-page-smoke': 404,
  '/v1/no-such-route-smoke': 404,
};

function fake(
  opts: {
    mcpOff?: boolean | 'wrong';
    drop?: { host: string; path: string; header: string };
    hits?: unknown[];
    cookieOn?: string;
  } = {},
) {
  const seen: string[] = [];
  const fetchImpl = async (url: string, init: { method?: string; headers?: Record<string, string> } = {}) => {
    seen.push(url);
    const u = new URL(url);
    const headers: Record<string, string> = { ...GOOD };
    const isApi = u.hostname === 'api.test';
    headers['content-type'] = isApi ? 'application/json' : 'text/html';
    let status = STATUS[u.pathname] ?? 200;
    if (opts.mcpOff && u.pathname.includes('mcp')) {
      if (opts.cookieOn === u.pathname) headers['set-cookie'] = '__session=x';
      return new Response('{}', { status: opts.mcpOff === true ? 404 : 405, headers });
    }
    let body: string | null = null;
    if (u.pathname === '/.well-known/oauth-protected-resource/mcp') {
      headers['content-type'] = 'application/json';
      body = JSON.stringify({
        resource: 'https://web.test/mcp',
        authorization_servers: ['https://clerk.test'],
        scopes_supported: ['mti:read', 'mti:watch'],
        bearer_methods_supported: ['header'],
      });
    } else if (u.pathname === '/mcp/server-card') {
      headers['content-type'] = 'application/mcp-server-card+json';
      headers['access-control-allow-origin'] = '*';
      headers.etag = '"abc123"';
      if (init.headers?.['If-None-Match'] === '"abc123"') {
        status = 304;
        body = '';
      } else body = '{}';
    } else if (u.pathname === '/mcp' && init.method === 'POST') {
      status = 401;
      headers['content-type'] = 'application/json';
      headers['www-authenticate'] =
        'Bearer resource_metadata="https://web.test/.well-known/oauth-protected-resource/mcp", scope="mti:read"';
    }
    if (opts.drop && opts.drop.host === u.hostname && opts.drop.path === u.pathname)
      delete headers[opts.drop.header];
    if (opts.cookieOn === u.pathname) headers['set-cookie'] = '__session=x';
    body ??=
      u.pathname === '/v1/search' ? JSON.stringify({ hits: opts.hits ?? [{ key: 'CVE-2025-1' }] }) : '{}';
    return new Response(status === 304 ? null : body, { status, headers });
  };
  return { fetchImpl, seen };
}
const cfg = { web: 'https://web.test/', api: 'https://api.test' };

describe('runSmoke', () => {
  it('passes against a healthy pair, within 43 requests', async () => {
    const { fetchImpl, seen } = fake();
    const rows = await runSmoke(fetchImpl, cfg);
    expect(rows.filter((r: { result: string }) => r.result !== 'ok')).toEqual([]);
    expect(seen.length).toBeLessThanOrEqual(43);
    expect(seen.some((u) => u.endsWith('/v1/search?q=apache'))).toBe(true);
    expect(seen.some((u) => u.endsWith('/e/CVE-2025-1'))).toBe(true);
    expect(seen.some((u) => u.endsWith('/v1/entries/CVE-2025-1'))).toBe(true);
  });

  it('checks /mcp (405), the metadata, the server card and the no-token 401 on the web host', async () => {
    const { fetchImpl, seen } = fake();
    const rows = await runSmoke(fetchImpl, cfg);
    for (const [check, status] of [
      ['web /mcp', 405],
      ['web /.well-known/oauth-protected-resource/mcp', 200],
      ['web /mcp/server-card', 200],
      ['web /mcp/server-card (If-None-Match)', 304],
      ['web POST /mcp (no token)', 401],
    ] as const)
      expect(rows.find((r: { check: string }) => r.check === check)).toMatchObject({ status, result: 'ok' });
    expect(seen).toContain('https://web.test/mcp');
    const noHsts = await runSmoke(
      fake({ drop: { host: 'web.test', path: '/mcp', header: 'strict-transport-security' } }).fetchImpl,
      cfg,
    );
    expect(noHsts.find((r: { check: string }) => r.check === 'web /mcp').result).toContain('no HSTS');
  });

  it('fails the no-token check when the challenge carries an error', async () => {
    const base = fake().fetchImpl;
    const fetchImpl = async (url: string, init: { method?: string; headers?: Record<string, string> }) => {
      const res = await base(url, init);
      if (init.method !== 'POST') return res;
      const headers = new Headers(res.headers);
      headers.set('www-authenticate', `${headers.get('www-authenticate')}, error="invalid_token"`);
      return new Response(await res.text(), { status: res.status, headers });
    };
    const rows = await runSmoke(fetchImpl, cfg);
    const bad = rows.filter((r: { result: string }) => r.result.startsWith('fail'));
    expect(bad.map((r: { check: string }) => r.check)).toEqual(['web POST /mcp (no token)']);
    expect(bad[0].result).toContain('error=');
  });

  it('fails an /mcp row that sets a cookie', async () => {
    for (const path of ['/mcp', '/mcp/server-card', '/.well-known/oauth-protected-resource/mcp']) {
      const rows = await runSmoke(fake({ cookieOn: path }).fetchImpl, cfg);
      const bad = rows.filter((r: { result: string }) => r.result.startsWith('fail'));
      expect(bad.length).toBeGreaterThan(0);
      for (const r of bad) expect(r.result).toContain('sets a cookie');
    }
  });

  it('skips the record checks when search finds nothing', async () => {
    const rows = await runSmoke(fake({ hits: [] }).fetchImpl, cfg);
    expect(rows.filter((r: { result: string }) => r.result.startsWith('skip')).length).toBe(2);
    // The only failure is the common-term check, which needs at least one hit.
    const failed = rows.filter((r: { result: string }) => r.result.startsWith('fail'));
    expect(failed.map((r: { check: string }) => r.check)).toEqual(['api /v1/search?q=apache']);
    expect(failed[0].result).toContain('no hits');
  });

  it('fails the row whose header is missing', async () => {
    const rows = await runSmoke(
      fake({ drop: { host: 'web.test', path: '/sources', header: 'strict-transport-security' } }).fetchImpl,
      cfg,
    );
    const bad = rows.filter((r: { result: string }) => r.result.startsWith('fail'));
    expect(bad).toHaveLength(1);
    expect(bad[0].check).toBe('web /sources');
    expect(bad[0].result).toContain('no HSTS');
  });

  it('fails an API row that is not JSON or lacks a request id', async () => {
    const rows = await runSmoke(
      fake({ drop: { host: 'api.test', path: '/v1/sources', header: 'x-request-id' } }).fetchImpl,
      cfg,
    );
    expect(rows.find((r: { check: string }) => r.check === 'api /v1/sources').result).toContain(
      'no x-request-id',
    );
  });

  it('--mcp off: the four MCP rows must be 404, the If-None-Match row is skipped, the rest is unchanged', async () => {
    const { fetchImpl, seen } = fake({ mcpOff: true });
    const rows = await runSmoke(fetchImpl, { ...cfg, mcp: 'off' });
    expect(rows.filter((r: { result: string }) => r.result.startsWith('fail'))).toEqual([]);
    const mcpRows = rows.filter((r: { check: string }) => r.check.includes('(MCP off)'));
    expect(mcpRows).toHaveLength(5);
    expect(mcpRows.filter((r: { status: unknown }) => r.status === 404)).toHaveLength(4);
    expect(mcpRows.filter((r: { result: string }) => r.result.startsWith('skip'))).toHaveLength(1);
    expect(seen.length).toBeLessThanOrEqual(43);
  });

  it('--mcp off fails when MCP answers (405), and when an MCP 404 sets a cookie', async () => {
    const rows = await runSmoke(fake({ mcpOff: 'wrong' }).fetchImpl, { ...cfg, mcp: 'off' });
    const bad = rows.filter((r: { result: string }) => r.result.startsWith('fail'));
    expect(bad).toHaveLength(4);
    for (const r of bad) expect(r.result).toContain('status 405, wanted 404');

    const withCookie = await runSmoke(fake({ mcpOff: true, cookieOn: '/mcp' }).fetchImpl, {
      ...cfg,
      mcp: 'off',
    });
    const cookieRows = withCookie.filter((r: { result: string }) => r.result.startsWith('fail'));
    expect(cookieRows.length).toBeGreaterThan(0);
    for (const r of cookieRows) expect(r.result).toContain('sets a cookie');
  });

  it('--mcp on is the default', async () => {
    const a = await runSmoke(fake().fetchImpl, cfg);
    const b = await runSmoke(fake().fetchImpl, { ...cfg, mcp: 'on' });
    expect(b).toEqual(a);
    // MCP 404s with --mcp on fail
    const rows = await runSmoke(fake({ mcpOff: true }).fetchImpl, { ...cfg, mcp: 'on' });
    expect(rows.filter((r: { result: string }) => r.result.startsWith('fail')).length).toBeGreaterThan(0);
  });
});
