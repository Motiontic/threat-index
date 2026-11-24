import { describe, expect, it, vi } from 'vitest';

vi.mock('cloudflare:workers', () => ({ env: {} }));

import { canonicalOrigin, parseSiteOrigin, workersDevRedirect } from '../app/lib/site.server';
import { loader as robots } from '../app/routes/robots';

const req = (url: string) => new Request(url);

describe('canonical origin', () => {
  it('uses the configured site URL, never the request host', () => {
    expect(canonicalOrigin(req('https://ti-web.acct.workers.dev/e/X'), 'https://mti.motiontic.com')).toBe(
      'https://mti.motiontic.com',
    );
    expect(
      canonicalOrigin(req('https://ti-web.acct.workers.dev/e/X'), 'https://mti.motiontic.com/path/'),
    ).toBe('https://mti.motiontic.com');
  });

  it('falls back to the request origin only when none is set or the value is unusable', () => {
    for (const bad of [undefined, '', '  ', 'nonsense', 'http://mti.motiontic.com', 'javascript:alert(1)'])
      expect(canonicalOrigin(req('http://localhost:8700/x'), bad)).toBe('http://localhost:8700');
    expect(parseSiteOrigin('http://localhost:8700')).toBe('http://localhost:8700');
  });

  it('robots.txt points its Sitemap line at the configured site URL', async () => {
    const res = robots({ request: req('https://ti-web.acct.workers.dev/robots.txt') } as never) as Response;
    expect(res.headers.get('Content-Type')).toContain('text/plain');
    // No SITE_ORIGIN in the mocked env: the request origin is the fallback.
    expect(await res.text()).toContain('Sitemap: https://ti-web.acct.workers.dev/sitemap.xml');
  });
});

describe('workersDevRedirect', () => {
  const site = 'https://mti.motiontic.com';
  it('redirects production on workers.dev only', () => {
    const r = workersDevRedirect(req('https://ti-web.a.workers.dev/search?q=x'), {
      tiEnv: 'production',
      siteOrigin: site,
    });
    expect(r?.status).toBe(301);
    expect(r?.headers.get('Location')).toBe(`${site}/search?q=x`);
    expect(
      workersDevRedirect(req('https://ti-web.a.workers.dev/'), { tiEnv: 'staging', siteOrigin: site }),
    ).toBeNull();
    expect(
      workersDevRedirect(req('https://other.example/'), { tiEnv: 'production', siteOrigin: site }),
    ).toBeNull();
  });

  it('keeps protocol-relative and backslash paths on the site host', () => {
    for (const path of ['//evil.com/x', '/\\evil.com/x', '///evil.com', '//evil.com@x/?a=1']) {
      const r = workersDevRedirect(req(`https://ti-web.a.workers.dev${path}`), {
        tiEnv: 'production',
        siteOrigin: site,
      });
      expect(new URL(r?.headers.get('Location') ?? '').origin).toBe(site);
    }
  });
});
