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
  '/no-such-page-smoke': 404,
  '/v1/no-such-route-smoke': 404,
};

function fake(opts: { drop?: { host: string; path: string; header: string }; hits?: unknown[] } = {}) {
  const seen: string[] = [];
  const fetchImpl = async (url: string) => {
    seen.push(url);
    const u = new URL(url);
    const headers: Record<string, string> = { ...GOOD };
    const isApi = u.hostname === 'api.test';
    headers['content-type'] = isApi ? 'application/json' : 'text/html';
    if (opts.drop && opts.drop.host === u.hostname && opts.drop.path === u.pathname)
      delete headers[opts.drop.header];
    const body =
      u.pathname === '/v1/search' ? JSON.stringify({ hits: opts.hits ?? [{ key: 'CVE-2025-1' }] }) : '{}';
    return new Response(body, { status: STATUS[u.pathname] ?? 200, headers });
  };
  return { fetchImpl, seen };
}
const cfg = { web: 'https://web.test/', api: 'https://api.test' };

describe('runSmoke', () => {
  it('passes against a healthy pair, within 40 requests', async () => {
    const { fetchImpl, seen } = fake();
    const rows = await runSmoke(fetchImpl, cfg);
    expect(rows.filter((r: { result: string }) => r.result !== 'ok')).toEqual([]);
    expect(seen.length).toBeLessThanOrEqual(40);
    expect(seen.some((u) => u.endsWith('/v1/search?q=apache'))).toBe(true);
    expect(seen.some((u) => u.endsWith('/e/CVE-2025-1'))).toBe(true);
    expect(seen.some((u) => u.endsWith('/v1/entries/CVE-2025-1'))).toBe(true);
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
});
