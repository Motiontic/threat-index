import type { ComponentProps } from 'react';
import { renderToString } from 'react-dom/server';
import { StaticRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { ApiBadRequest, ApiUnavailable, createSiteData, worldQuery } from '../app/data/api.server';
import { fixtureApi } from '../app/data/fixture-api.server';
import {
  guardBreachDetail,
  guardBreachList,
  guardIncidentDetail,
  guardTechniqueDetail,
  MAX_CHILDREN,
  MAX_ITEMS,
  MAX_NOTICES,
  MAX_VULNS,
} from '../app/data/world-guards';
import { countLine, parseWorldParams, worldHref } from '../app/lib/world';
import { fakeApi } from './fake-api';

// Searches and pages go through the in-process fixture API, with every request recorded.
const seen = vi.hoisted(() => ({ requests: [] as string[] }));
vi.mock('../app/data/data.server', async () => {
  const { createSiteData: create } = await import('../app/data/api.server');
  const { fixtureApi: fixtures } = await import('../app/data/fixture-api.server');
  const api = {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input as RequestInfo, init);
      seen.requests.push(new URL(req.url).pathname + new URL(req.url).search);
      return fixtures(req);
    },
  };
  return { getData: () => create(api, 'fixtures') };
});

import { default as Breach, loader as breachLoader, meta as breachMeta } from '../app/routes/breach';
import { loader as breachesLoader, meta as breachesMeta } from '../app/routes/breaches';
import { loader as incidentsLoader, meta as incidentsMeta } from '../app/routes/incidents';
import { loader as searchLoader } from '../app/routes/search';

const CREDIT = { sourceId: 'hibp', name: 'HIBP', text: 'Source: HIBP' };
const NOTICE = { source: 'hibp', noticeId: 'n1', name: 'Acme', display: 'full' as const };
const SUMMARY = {
  key: 'k',
  company: { key: 'c', name: 'Acme' },
  firstSeen: '2024-01-01',
  noticeCount: 1,
  counts: [],
  jurisdictions: [],
  sources: ['hibp'],
};
const site = (routes: Parameters<typeof fakeApi>[0]) => {
  const f = fakeApi(routes);
  return { ...f, data: createSiteData(f.api, 'api') };
};
const metaOf = (tags: Record<string, string>[], key: string) =>
  tags.find((t) => t.name === key || t.rel === key || t.title !== undefined);
const robots = (tags: Record<string, string>[]) => tags.find((t) => t.name === 'robots')?.content;
const canonical = (tags: Record<string, string>[]) => tags.find((t) => t.rel === 'canonical')?.href;

describe('request building', () => {
  it('encodes path segments, builds queries in a fixed order, sends no visitor headers', async () => {
    const { data, requests } = site({
      '/v1/breaches?q=acme&page=2': { body: { items: [], page: 2, next: null, credits: [] } },
      '/v1/breaches/domain%3Aexample.com%402025-03-04': { status: 404 },
      '/v1/incidents/avid/a%2Fb': { status: 404 },
      '/v1/incidents?kind=ai&kind=cyber': { body: { items: [], page: 1, next: null, credits: [] } },
      '/v1/techniques/T1190': { status: 404 },
      '/v1/techniques?framework=cwe': { body: { items: [], page: 1, next: null, credits: [] } },
    });
    await data.breaches({ page: 2, q: 'acme' });
    expect(await data.breach('domain:example.com@2025-03-04')).toBeNull();
    expect(await data.incident('avid', 'a/b')).toBeNull();
    await data.incidents({ kind: ['ai', 'cyber'] });
    expect(await data.technique('T1190')).toBeNull();
    await data.techniques({ framework: ['cwe'] });
    expect(requests.map((r) => new URL(r.url).pathname + new URL(r.url).search)).toEqual([
      '/v1/breaches?q=acme&page=2',
      '/v1/breaches/domain%3Aexample.com%402025-03-04',
      '/v1/incidents/avid/a%2Fb',
      '/v1/incidents?kind=ai&kind=cyber',
      '/v1/techniques/T1190',
      '/v1/techniques?framework=cwe',
    ]);
    for (const r of requests) {
      expect(r.headers.get('authorization')).toBeNull();
      expect(r.headers.get('cookie')).toBeNull();
      expect([...r.headers.keys()]).toEqual(['accept']);
    }
    expect(worldQuery({ page: 1 })).toBe('');
  });

  it('maps 400 to ApiBadRequest and 5xx to ApiUnavailable', async () => {
    const { data } = site({
      '/v1/breaches?q=x': { status: 400, body: { error: 'bad_query' } },
      '/v1/techniques': { status: 500, body: {} },
    });
    await expect(data.breaches({ q: 'x' })).rejects.toBeInstanceOf(ApiBadRequest);
    await expect(data.techniques({})).rejects.toBeInstanceOf(ApiUnavailable);
  });
});

describe('guards', () => {
  it('drops a non-http(s) url and copies only known fields', () => {
    const d = guardBreachDetail({
      ...SUMMARY,
      credits: [CREDIT],
      extra: 'x',
      notices: [
        { ...NOTICE, url: 'javascript:alert(1)', secret: 'no' },
        { ...NOTICE, noticeId: 'n2', url: 'https://example.test/a' },
      ],
    });
    expect(d.notices[0]).toEqual(NOTICE);
    expect(d.notices[1]?.url).toBe('https://example.test/a');
    expect('extra' in d).toBe(false);
    const inc = guardIncidentDetail({
      source: 'avid',
      incidentId: 'i',
      kind: 'ai',
      title: 't',
      display: 'full',
      url: 'data:text/html,x',
      entities: [],
      techniques: [],
      credits: [],
    });
    expect('url' in inc).toBe(false);
  });

  it('keeps a link notice to its link fields even when the body carries more', () => {
    const d = guardBreachDetail({
      ...SUMMARY,
      credits: [],
      notices: [{ ...NOTICE, display: 'link', count: 99, countUnit: 'individuals', jurisdiction: 'FR' }],
    });
    expect(Object.keys(d.notices[0] ?? {}).sort()).toEqual(['display', 'name', 'noticeId', 'source']);
    const inc = guardIncidentDetail({
      source: 'databreaches-net',
      incidentId: 'i',
      kind: 'cyber_event',
      title: 't',
      display: 'link',
      entities: ['secret'],
      techniques: [{ id: 'T1190' }],
      credits: [],
    });
    expect(inc.entities).toEqual([]);
    expect(inc.techniques).toEqual([]);
  });

  it('rejects a body carrying a total, at any depth', () => {
    expect(() => guardBreachList({ items: [], page: 1, next: null, credits: [], total: 3 })).toThrow();
    expect(() =>
      guardBreachDetail({
        ...SUMMARY,
        credits: [],
        notices: [],
        counts: [{ unit: 'accounts', count: 1, total: 2 }],
      }),
    ).toThrow();
    expect(() =>
      guardBreachList({ items: [{ ...SUMMARY, total: 5 }], page: 1, next: null, credits: [] }),
    ).toThrow();
  });

  it('caps lists', () => {
    const list = guardBreachList({
      items: Array.from({ length: 40 }, (_, i) => ({ ...SUMMARY, key: `k${i}` })),
      page: 1,
      next: null,
      credits: [],
    });
    expect(list.items).toHaveLength(MAX_ITEMS);
    const d = guardBreachDetail({
      ...SUMMARY,
      credits: [],
      notices: Array.from({ length: 300 }, (_, i) => ({ ...NOTICE, noticeId: `n${i}` })),
    });
    expect(d.notices).toHaveLength(MAX_NOTICES);
    const t = guardTechniqueDetail({
      id: 'T1',
      framework: 'attack',
      name: 'n',
      credits: [],
      children: Array.from({ length: 300 }, (_, i) => ({ id: `T${i}`, framework: 'attack', name: 'c' })),
      vulns: Array.from({ length: 80 }, (_, i) => ({ key: `CVE-${i}`, title: 't', exploited: false })),
      vulnsMore: true,
    });
    expect(t.children).toHaveLength(MAX_CHILDREN);
    expect(t.vulns).toHaveLength(MAX_VULNS);
  });
});

describe('parameters and count lines', () => {
  it('validates the query string and keeps a fixed order', () => {
    const p = parseWorldParams(new URLSearchParams('page=3&q=%20acme%00&kind=bogus&kind=ai&kind=cyber'), {
      kind: ['ai', 'cyber_op', 'cyber_event', 'cyber'],
    });
    expect(p).toEqual({ page: 3, q: 'acme', kind: ['ai', 'cyber'] });
    expect(parseWorldParams(new URLSearchParams('page=99&q=' + 'a'.repeat(300))).page).toBe(1);
    expect(parseWorldParams(new URLSearchParams('page=2')).q).toBeUndefined();
    expect(worldHref('/incidents', { q: 'a b', kind: ['ai'] }, 2)).toBe('/incidents?q=a+b&page=2&kind=ai');
  });

  it('writes each count on its own, with its unit and place', () => {
    expect(countLine({ unit: 'state_residents', jurisdiction: 'CA', count: 500 })).toBe(
      '500 state residents · CA',
    );
    expect(countLine({ unit: 'individuals', jurisdiction: null, count: 1200 })).toBe('1,200 individuals');
    expect(countLine({ unit: 'not_stated', jurisdiction: null, count: 0 })).toBe('Count not stated');
    expect(countLine({ unit: 'claim', jurisdiction: null, count: 3000000 })).toBe(
      'Claimed by attacker: 3,000,000',
    );
  });
});

const render = (loaderData: unknown) =>
  renderToString(
    <StaticRouter location="/breach/x">
      <Breach {...({ loaderData } as unknown as ComponentProps<typeof Breach>)} />
    </StaticRouter>,
  )
    .replace(/<!-- -->/g, '')
    .replace(/ data-discover="true"/g, '');

describe('pages', () => {
  it('renders the breach page with separate count lines, a link-only row and no sum', async () => {
    const two = (await breachLoader({
      request: new Request('https://web.test/breach/x'),
      params: { key: 'domain:example.com@2025-03-04' },
    } as never)) as { breach: unknown };
    const html = render(two);
    expect(html).toContain('500 state residents · CA');
    expect(html).toContain('1,200 individuals');
    expect(html).not.toMatch(/\btotal\b/i);
    expect(html).not.toMatch(/\bin all\b/i);
    expect(html).not.toContain('1,700');
    expect(html).toContain('Sources and credits');

    const claim = (await breachLoader({
      request: new Request('https://web.test/breach/x'),
      params: { key: 'domain:example.com@2025-01-15' },
    } as never)) as { breach: unknown };
    const linkHtml = render(claim);
    expect(linkHtml).toContain('Claimed by attacker: 3,000,000');
    expect(linkHtml).toContain('Link only');
    // the link row shows name, date and the link; no count cell text
    const row = linkHtml.split('<tr>').find((r) => r.includes('Link only')) ?? '';
    expect(row).toContain('Read at source');
    expect(row).not.toMatch(/individuals|accounts|Count not stated/);
  });

  it('answers a missing or malformed breach with a 404 and a down API with 502', async () => {
    for (const key of ['no-such', 'café']) {
      const res = await breachLoader({
        request: new Request('https://web.test/breach/x'),
        params: { key },
      } as never).catch((e: Response) => e);
      expect(res).toMatchObject({ init: { status: 404 } });
    }
  });

  it('meta: detail pages are indexable with a canonical and a data-built description', async () => {
    const loaded = (await breachLoader({
      request: new Request('https://web.test/breach/x'),
      params: { key: 'domain:example.com@2025-03-04' },
    } as never)) as never;
    const tags = breachMeta({ loaderData: loaded } as never) as Record<string, string>[];
    expect(robots(tags)).toBeUndefined();
    expect(canonical(tags)).toBe('https://web.test/breach/domain%3Aexample.com%402025-03-04');
    expect(tags.find((t) => t.name === 'description')?.content).toBe(
      'Breach notices for Example Co.: 2 notices, first reported 2025-03-04.',
    );
    expect(metaOf(tags, 'title')).toBeDefined();
  });

  it('meta: lists are indexable only on page 1 with no q or filter', async () => {
    const meta = async (loader: typeof breachesLoader, m: typeof breachesMeta, qs: string) => {
      const loaderData = await loader({ request: new Request(`https://web.test/x${qs}`) } as never);
      return robots(m({ loaderData } as never) as Record<string, string>[]);
    };
    expect(await meta(breachesLoader, breachesMeta, '')).toBeUndefined();
    expect(await meta(breachesLoader, breachesMeta, '?q=example')).toBe('noindex');
    expect(await meta(breachesLoader, breachesMeta, '?page=2')).toBe('noindex');
    expect(await meta(incidentsLoader as never, incidentsMeta as never, '')).toBeUndefined();
    expect(await meta(incidentsLoader as never, incidentsMeta as never, '?kind=ai')).toBe('noindex');
  });
});

describe('search', () => {
  it('type=breach calls /v1/breaches?q=… and not /v1/search', async () => {
    seen.requests.length = 0;
    const res = (await searchLoader({
      request: new Request('https://web.test/search?type=breach&q=example'),
    } as never)) as {
      outcome: string;
      sections: { type: string; rows: unknown[]; moreTo: string }[];
      searched: boolean;
    };
    expect(seen.requests).toEqual(['/v1/breaches?q=example']);
    expect(res.outcome).toBe('results');
    expect(res.searched).toBe(false);
    expect(res.sections[0]?.type).toBe('breach');
    expect(res.sections[0]?.rows.length).toBeGreaterThan(0);
    expect(res.sections[0]?.moreTo).toBe('/breaches?q=example');
  });

  it('maps ai, tech and term to their list endpoints; vuln keeps /v1/search', async () => {
    seen.requests.length = 0;
    await searchLoader({
      request: new Request('https://web.test/search?type=ai&type=tech&type=term&q=x'),
    } as never);
    expect(seen.requests.sort()).toEqual([
      '/v1/incidents?q=x&kind=ai',
      '/v1/techniques?q=x&framework=attack&framework=atlas&framework=capec',
      '/v1/techniques?q=x&framework=cwe',
    ]);
    seen.requests.length = 0;
    await searchLoader({ request: new Request('https://web.test/search?type=vuln&q=log4j') } as never);
    expect(seen.requests).toHaveLength(1);
    expect(seen.requests[0]).toMatch(/^\/v1\/search\?/);
    seen.requests.length = 0;
    await searchLoader({ request: new Request('https://web.test/search?q=log4j') } as never);
    expect(seen.requests[0]).toMatch(/^\/v1\/search\?q=log4j$/);
  });
});

describe('fixture API', () => {
  it('answers the six routes with the API status codes and never a total', async () => {
    const get = (p: string) => fixtureApi(new Request(`https://x.test${p}`));
    for (const p of [
      '/v1/breaches',
      '/v1/incidents?kind=cyber',
      '/v1/techniques?framework=attack',
      '/v1/techniques/T1195',
      '/v1/incidents/avid/EXAMPLE-AVID-1',
    ]) {
      const res = await get(p);
      expect(res.status, p).toBe(200);
      expect(await res.text()).not.toMatch(/"total"/);
    }
    expect((await get('/v1/breaches/nope')).status).toBe(404);
    expect((await get('/v1/breaches?page=0')).status).toBe(400);
    expect((await get('/v1/incidents?kind=x')).status).toBe(400);
    expect((await get('/v1/techniques/foo')).status).toBe(400);
    expect((await get('/v1/techniques/T9999')).status).toBe(404);
  });
});
