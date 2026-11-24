import { describe, expect, it, vi } from 'vitest';

vi.mock('cloudflare:workers', () => ({ env: { SITE_ORIGIN: 'https://mti.motiontic.com' } }));

import { loader } from '../app/routes/robots';

describe('/robots.txt with a configured site URL', () => {
  it('never uses the request host', async () => {
    const res = loader({
      request: new Request('https://ti-web.acct.workers.dev/robots.txt'),
    } as never) as Response;
    const text = await res.text();
    expect(text).toContain('Sitemap: https://mti.motiontic.com/sitemap.xml');
    expect(text).not.toContain('workers.dev');
  });
});
