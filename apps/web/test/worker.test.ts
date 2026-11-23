import { beforeEach, describe, expect, it, vi } from 'vitest';
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
