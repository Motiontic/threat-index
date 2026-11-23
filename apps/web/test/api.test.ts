import { describe, expect, it } from 'vitest';
import {
  ApiBadRequest,
  ApiUnavailable,
  createSiteData,
  MAX_BODY_BYTES,
  searchQuery,
} from '../app/data/api.server';
import { displayType } from '../app/data/display';
import { guardEntryResponse, guardSearchResponse, guardSources } from '../app/data/guards';
import { dataMode } from '../app/data/mode.server';
import { parseSearchParams } from '../app/lib/search-params';
import { CREDIT, fakeApi, PREVIEW } from './fake-api';

const site = (routes: Parameters<typeof fakeApi>[0]) => {
  const f = fakeApi(routes);
  return { ...f, data: createSiteData(f.api, 'api', { requestId: 'req-test-0001', ip: null }) };
};

describe('request building', () => {
  it('asks for entries by encoded id, as JSON, with no visitor headers', async () => {
    const { data, requests } = site({
      '/v1/entries/a%2Fb%20c': { body: { access: 'preview', entry: PREVIEW } },
    });
    await data.entry('a/b c');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe('https://ti-api.internal/v1/entries/a%2Fb%20c');
    expect(requests[0]?.method).toBe('GET');
    expect(requests[0]?.headers.get('accept')).toBe('application/json');
    expect(requests[0]?.signal).toBeDefined();
  });

  it('never sends Cookie or Authorization, even when the incoming request has them', async () => {
    const { data, requests } = site({ '/v1/sources': { body: { sources: [] } } });
    const incoming = new Request('https://web.test/sources', {
      headers: { Cookie: '__session=secret', Authorization: 'Bearer secret', 'X-Other': '1' },
    });
    expect(incoming.headers.get('cookie')).toBe('__session=secret');
    // The client has no way to receive the incoming request: it builds its own.
    await data.sources();
    const sent = requests[0]?.headers;
    expect(sent?.get('cookie')).toBeNull();
    expect(sent?.get('authorization')).toBeNull();
    expect([...(sent?.keys() ?? [])].sort()).toEqual(['accept', 'x-request-id']);
  });

  it('encodes index letters and passes the cursor', async () => {
    const { data, requests } = site({
      '/v1/index/c': { body: { letter: 'c', items: [] } },
      '/v1/index/c?cursor=abc': { body: { letter: 'c', items: [] } },
    });
    await data.index('c');
    await data.index('c', 'abc');
    expect(requests.map((r) => new URL(r.url).pathname + new URL(r.url).search)).toEqual([
      '/v1/index/c',
      '/v1/index/c?cursor=abc',
    ]);
  });

  it('builds the exact query string for each filter', () => {
    expect(searchQuery({ q: 'log4j' })).toBe('?q=log4j');
    expect(searchQuery({ type: ['vuln', 'mal'] })).toBe('?type=vuln&type=mal');
    expect(searchQuery({ sig: ['kev'], sort: 'new' })).toBe('?sig=kev&sort=new');
    expect(searchQuery({ sev: 'critical', year: '2021' })).toBe('?sev=critical&year=2021');
    expect(searchQuery({ q: 'a b&c', cursor: 'x_-1' })).toBe('?q=a+b%26c&cursor=x_-1');
    expect(searchQuery({})).toBe('');
  });

  it('drops unknown values and enforces q and cursor limits', () => {
    const p = parseSearchParams(
      new URLSearchParams(
        'q=%20hi%20&type=vuln&type=bogus&sig=nope&sev=huge&year=1850&sort=zig&cursor=a%20b&evil=1',
      ),
    );
    expect(p).toEqual({ q: 'hi', type: ['vuln'] });
    expect(searchQuery(p)).toBe('?q=hi&type=vuln');
    expect(parseSearchParams(new URLSearchParams(`q=${'a'.repeat(500)}`)).q).toHaveLength(200);
    expect(parseSearchParams(new URLSearchParams(`cursor=${'a'.repeat(201)}`)).cursor).toBeUndefined();
    expect(parseSearchParams(new URLSearchParams(`cursor=${'a'.repeat(200)}`)).cursor).toHaveLength(200);
    expect(parseSearchParams(new URLSearchParams('year=2021&sev=high&sig=kev&sort=new'))).toEqual({
      sig: ['kev'],
      sev: 'high',
      year: '2021',
      sort: 'new',
    });
  });

  it('asks for the sitemap', async () => {
    const { data, requests } = site({
      '/v1/sitemap.xml': { text: '<urlset/>', headers: { 'Content-Type': 'application/xml' } },
    });
    expect(await data.sitemap()).not.toBeNull();
    expect(new URL(requests[0]?.url ?? '').pathname).toBe('/v1/sitemap.xml');
  });
});

describe('responses', () => {
  it('accepts the contract shapes', async () => {
    const { data } = site({
      '/v1/entries/CVE-2025-1': { body: { access: 'preview', entry: PREVIEW } },
      '/v1/search?q=x': {
        body: {
          query: 'x',
          hits: [{ key: 'K', title: 't', summary: 's', exploited: false }],
          total: 1,
          credits: [CREDIT],
        },
      },
      '/v1/sources': {
        body: {
          sources: [
            {
              id: 'a',
              name: 'A',
              gives: 'g',
              pattern: 'git',
              cadence: 'daily',
              licence: 'on',
              display: 'full',
              credit: 'c',
            },
          ],
        },
      },
    });
    expect((await data.entry('CVE-2025-1'))?.credits).toEqual([CREDIT]);
    expect((await data.search({ q: 'x' })).total).toBe(1);
    expect((await data.sources()).sources[0]?.id).toBe('a');
  });

  it('rejects missing required fields', () => {
    expect(() =>
      guardEntryResponse({ access: 'preview', entry: { ...PREVIEW, exploited: undefined } }),
    ).toThrow();
    expect(() => guardEntryResponse({ access: 'preview', entry: { ...PREVIEW, key: 1 } })).toThrow();
    expect(() => guardEntryResponse({ access: 'weird', entry: PREVIEW })).toThrow();
    expect(() => guardSearchResponse({ query: 'x', hits: [{ key: 'K' }], total: 1, credits: [] })).toThrow();
    expect(() => guardSearchResponse({ query: 'x', hits: [], credits: [] })).toThrow();
    expect(() => guardSources({ sources: [{ id: 'a' }] })).toThrow();
    expect(() => guardSources(null)).toThrow();
  });

  it('reduces an access:full response to the preview fields', async () => {
    const full = {
      access: 'full',
      entry: {
        ...PREVIEW,
        cvss: 9.8,
        cwe: ['CWE-306'],
        advisories: [{ source: 'x', secret: 'full-only' }],
        signals: [{ kind: 'kev' }],
        changes: [{ at: 'now' }],
        internalNote: 'never render',
      },
    };
    const { data } = site({ '/v1/entries/CVE-2025-1': { body: full } });
    const entry = await data.entry('CVE-2025-1');
    expect(Object.keys(entry ?? {}).sort()).toEqual(
      ['aliases', 'credits', 'cvss', 'exploited', 'key', 'kind', 'summary', 'title'].sort(),
    );
    expect(JSON.stringify(entry)).not.toMatch(/full-only|never render|CWE-306/);
  });

  it('maps 404 to null', async () => {
    const { data } = site({});
    expect(await data.entry('CVE-1999-1')).toBeNull();
    expect(await data.index('q')).toBeNull();
  });

  it('maps 400 to ApiBadRequest carrying the message', async () => {
    const { data } = site({ '/v1/search?q=x': { status: 400, body: { error: 'nope' } } });
    await expect(data.search({ q: 'x' })).rejects.toThrow(ApiBadRequest);
    await expect(data.search({ q: 'x' })).rejects.toThrow('nope');
  });

  it('maps 500, timeout, network error, oversized and invalid JSON to ApiUnavailable', async () => {
    const cases: Parameters<typeof fakeApi>[0][] = [
      { '/v1/sources': { status: 500, body: {} } },
      { '/v1/sources': { throws: new DOMException('timed out', 'TimeoutError') } },
      { '/v1/sources': { throws: new TypeError('network') } },
      { '/v1/sources': { text: 'x'.repeat(MAX_BODY_BYTES + 1) } },
      { '/v1/sources': { text: '{not json' } },
      { '/v1/sources': { body: { sources: [{ id: 1 }] } } },
      { '/v1/sources': { status: 404 } },
    ];
    for (const routes of cases) {
      const { data } = site(routes);
      await expect(data.sources()).rejects.toThrow(ApiUnavailable);
    }
  });

  it('returns the sitemap only for 200 with an XML type', async () => {
    const xml = { 'Content-Type': 'application/xml' };
    expect(await site({ '/v1/sitemap.xml': { text: '<a/>', headers: xml } }).data.sitemap()).not.toBeNull();
    expect(
      await site({ '/v1/sitemap.xml': { text: '<a/>', status: 500, headers: xml } }).data.sitemap(),
    ).toBeNull();
    expect(await site({ '/v1/sitemap.xml': { text: '<a/>' } }).data.sitemap()).toBeNull();
    expect(await site({}).data.sitemap()).toBeNull();
  });
});

describe('dataMode', () => {
  const API = {} as Fetcher;
  it('is api only with DATA_SOURCE=api and a binding', () => {
    expect(dataMode({ DATA_SOURCE: 'api', API })).toBe('api');
    expect(dataMode({ DATA_SOURCE: 'api' })).toBe('fixtures');
    expect(dataMode({ DATA_SOURCE: 'fixtures', API })).toBe('fixtures');
    expect(dataMode({ API })).toBe('fixtures');
    expect(dataMode({})).toBe('fixtures');
  });
});

describe('displayType', () => {
  it('maps kinds', () => {
    expect(displayType('mal')).toBe('mal');
    for (const k of ['cve', 'ghsa', 'osv', 'euvd', 'other']) expect(displayType(k)).toBe('vuln');
    for (const k of ['breach', 'ai', 'tech', 'term'] as const) expect(displayType(k)).toBe(k);
  });
  it('falls back to the key prefix', () => {
    expect(displayType(undefined, 'MAL-2025-1')).toBe('mal');
    expect(displayType(undefined, 'CVE-2025-1')).toBe('vuln');
    expect(displayType()).toBe('vuln');
  });
});
