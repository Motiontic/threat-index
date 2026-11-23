import { describe, expect, it } from 'vitest';
import { createAccountClient, createSiteData } from '../app/data/api.server';
import { fakeApi, PREVIEW } from './fake-api';
import { readWeb } from './read-app';

describe('public data calls', () => {
  it('never carry Authorization or Cookie, even when a session exists elsewhere in the same Worker', async () => {
    const f = fakeApi({
      '/v1/entries/CVE-2025-1': { body: { access: 'preview', entry: PREVIEW } },
      '/v1/search': { body: { query: 'q', hits: [], total: 0, credits: [] } },
      '/v1/index/a': { body: { letter: 'a', items: [] } },
      '/v1/sources': { body: { sources: [] } },
      '/v1/sitemap.xml': { text: '<urlset/>', headers: { 'content-type': 'application/xml' } },
    });
    // A signed-in visitor's client exists on the same binding...
    const account = createAccountClient(f.api, 'session.token', { requestId: 'req-test-0001', ip: null });
    await account.entryFull('CVE-2025-1').catch(() => {});
    f.requests.length = 0;
    // ...and the public client still sends nothing of it.
    const site = createSiteData(f.api, 'api', { requestId: 'req-test-0001', ip: null });
    await site.entry('CVE-2025-1');
    await site.search({ q: 'q' });
    await site.index('a');
    await site.sources();
    await site.sitemap();
    expect(f.requests).toHaveLength(5);
    for (const r of f.requests) {
      expect(r.headers.get('authorization')).toBeNull();
      expect(r.headers.get('cookie')).toBeNull();
    }
  });

  it('has no Authorization or Cookie in the public client source', () => {
    const server = readWeb('app/data/api.server.ts');
    const publicClient = server.slice(
      server.indexOf('export function createSiteData'),
      server.indexOf('/**\n * The account calls'),
    );
    expect(publicClient).not.toMatch(/authorization|cookie/i);
  });

  it('getData reads only the request id and the client IP from the request', () => {
    const src = readWeb('app/data/data.server.ts');
    const ctx = src.slice(
      src.indexOf('export function clientContext'),
      src.indexOf('/** What every loader calls'),
    );
    expect(ctx).toContain('request.headers.get(REQUEST_ID_HEADER)');
    expect(ctx).toContain("request.headers.get('cf-connecting-ip')");
    expect(ctx.match(/request\.headers\.get/g)).toHaveLength(2);
    const body = src.slice(src.indexOf('export function getData'), src.indexOf('const fixtureFetch'));
    expect(body.match(/\brequest\b/g)).toHaveLength(2); // the parameter and clientContext(request)
  });
});
