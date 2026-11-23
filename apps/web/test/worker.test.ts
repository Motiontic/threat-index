import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BASE_HEADERS } from '../app/lib/security.server';

const handle = vi.hoisted(() => vi.fn());

vi.mock('cloudflare:workers', () => ({ env: { TI_ENV: 'production' } }));
vi.mock('virtual:react-router/server-build', () => ({}));
vi.mock('react-router', () => ({ createRequestHandler: () => handle }));

import worker from '../workers/app';

const call = (req: Request) => (worker.fetch as (r: Request) => Promise<Response>)(req);

describe('Worker fetch handler', () => {
  beforeEach(() => handle.mockReset());

  it('gives a loader redirect the document headers, a CSP nonce and noindex', async () => {
    handle.mockResolvedValue(new Response(null, { status: 301, headers: { Location: '/e/CVE-2025-3248' } }));
    const res = await call(new Request('https://example.test/e/cve-2025-3248'));
    expect(res.status).toBe(301);
    expect(res.headers.get('Location')).toBe('/e/CVE-2025-3248');
    for (const name of Object.keys(BASE_HEADERS))
      expect(res.headers.get(name), name).toBe(BASE_HEADERS[name]);
    expect(res.headers.get('X-Robots-Tag')).toBe('noindex');
    expect(res.headers.get('Content-Security-Policy')).toMatch(/script-src 'self' 'nonce-[\w-]+/);
  });

  it('passes a document response through untouched', async () => {
    const doc = new Response('<html></html>', { status: 200 });
    handle.mockResolvedValue(doc);
    expect(await call(new Request('https://example.test/'))).toBe(doc);
  });
});
