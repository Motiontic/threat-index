import type { ComponentProps } from 'react';
import { renderToString } from 'react-dom/server';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { createSiteData } from '../app/data/api.server';
import { fixtureApi } from '../app/data/fixture-api.server';
import { guardHome } from '../app/data/guards';
import type { HomeResponse } from '../app/data/types';

vi.mock('cloudflare:workers', () => ({ env: {} }));
vi.mock('../app/data/data.server', async () => {
  const { createSiteData: create } = await import('../app/data/api.server');
  const { fixtureApi: fixtures } = await import('../app/data/fixture-api.server');
  const api = { fetch: (input: RequestInfo | URL, init?: RequestInit) => fixtures(new Request(input, init)) };
  return { getData: () => create(api, 'fixtures', { requestId: 'req-test-0001', ip: null }) };
});

import { default as Home, loader as homeLoader } from '../app/routes/home';
import { default as Incidents } from '../app/routes/incidents';

const site = () =>
  createSiteData({ fetch: (i, init) => fixtureApi(new Request(i, init)) }, 'fixtures', {
    requestId: 'req-test-0001',
    ip: null,
  });

// A memory router is a data router, which the search form's `Form` needs; `renderToString` renders it once.
const render = (node: React.ReactElement) =>
  renderToString(<RouterProvider router={createMemoryRouter([{ path: '/', element: node }])} />);

const EMPTY: HomeResponse = {
  counts: {
    vulnerabilities: 0,
    exploited: 0,
    exploits: 0,
    breaches: 0,
    aiIncidents: 0,
    cyberOperations: 0,
    maliciousPackages: 0,
    techniques: 0,
  },
  lists: {
    exploited: [],
    vulnerabilities: [],
    exploits: [],
    breaches: [],
    aiIncidents: [],
    maliciousPackages: [],
  },
  changes: [],
};
const homeHtml = (home: HomeResponse | null) =>
  render(
    <Home
      {...({ loaderData: { origin: 'https://x.test', home } } as unknown as ComponentProps<typeof Home>)}
    />,
  );

describe('home page', () => {
  it('renders count tiles and the panels from the fixtures', async () => {
    const loaderData = await homeLoader({
      request: new Request('https://x.test/'),
    } as Parameters<typeof homeLoader>[0]);
    expect(loaderData.home).not.toBeNull();
    const html = render(<Home {...({ loaderData } as unknown as ComponentProps<typeof Home>)} />);
    for (const title of [
      'Exploited in the wild, latest',
      'Latest vulnerabilities',
      'Recent breaches',
      'What changed',
      'Browse by type',
    ])
      expect(html).toContain(title);
    // Count tiles link to their lists and show a number.
    expect(html).toMatch(/href="\/search\?type=vuln"[^>]*>.*?tile-count">\d+/);
    expect(html).toContain('href="/breaches"');
    expect(html).toContain('href="/incidents?kind=ai"');
    // Each panel has a See all link to its filtered list.
    expect(html).toMatch(/href="\/search\?sig=kev"[^>]*>See all/);
    expect(html).toMatch(/href="\/breaches"[^>]*>See all/);
    expect(html).toContain('CISA KEV');
  });

  it('leaves out panels with no items and marks zero tiles', () => {
    const html = homeHtml({
      ...EMPTY,
      counts: { ...EMPTY.counts, vulnerabilities: 3 },
      lists: {
        ...EMPTY.lists,
        vulnerabilities: [{ key: 'CVE-2025-1', title: 'Only flaw', type: 'vuln', date: '2025-03-01' }],
      },
    });
    expect(html).toContain('Latest vulnerabilities');
    expect(html).toContain('Only flaw');
    for (const gone of [
      'Exploited in the wild, latest',
      'Recent breaches',
      'Recent AI incidents',
      'Latest public exploits',
      'Latest malicious packages',
      'What changed',
    ])
      expect(html).not.toContain(gone);
    expect(html).toContain('tile-count">0');
    expect(html).toContain('Coming soon');
  });

  it('still renders the hero and search when the API is down', () => {
    const html = homeHtml(null);
    expect(html).toContain('in one place');
    expect(html).not.toContain('tile-count');
    expect(html).toContain('Browse by type');
  });
});

describe('home guard', () => {
  it('copies known fields, caps lists at 10 and refuses a bad body', () => {
    const item = (n: number) => ({ key: `k${n}`, title: 't', type: 'vuln', extra: 'drop' });
    const body = {
      ...EMPTY,
      lists: { ...EMPTY.lists, vulnerabilities: Array.from({ length: 15 }, (_, i) => item(i)) },
    };
    const out = guardHome(body);
    expect(out.lists.vulnerabilities).toHaveLength(10);
    expect(out.lists.vulnerabilities[0]).toEqual({ key: 'k0', title: 't', type: 'vuln' });
    expect(() => guardHome({ ...EMPTY, counts: { vulnerabilities: 'x' } })).toThrow();
    expect(() =>
      guardHome({ ...body, lists: { ...EMPTY.lists, exploited: [{ key: 'a', title: 'b', type: 'zzz' }] } }),
    ).toThrow();
  });

  it('is requested as /v1/home and parsed', async () => {
    const home = await site().home();
    expect(home.counts.vulnerabilities).toBeGreaterThan(0);
    expect(home.lists.exploited.length).toBeLessThanOrEqual(10);
  });
});

describe('empty list states', () => {
  const incidents = (params: object, items: unknown[] = []) =>
    render(
      <Incidents
        {...({
          loaderData: { origin: 'https://x.test', params, items, next: null, credits: [] },
        } as unknown as ComponentProps<typeof Incidents>)}
      />,
    );

  it('says there are no records yet when the type is empty', () => {
    const html = incidents({ page: 1, kind: ['ai'] });
    expect(html).toContain('No AI incidents yet');
    expect(html).toContain('href="/sources"');
    expect(html).not.toContain('No matching incidents');
  });

  it('keeps "no matches" for a query on a list', () => {
    const html = incidents({ page: 1, q: 'zzz' });
    expect(html).toContain('No matching incidents');
    expect(html).not.toContain('yet');
  });
});
