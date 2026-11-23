import { fixtureApi } from '../../app/data/fixture-api.server';

const SITEMAP = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://threatindex.example/e/CVE-2025-3248</loc></url>
<url><loc>https://threatindex.example/e/CVE-2021-44228</loc></url>
</urlset>
`;

export default {
  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    // Test hooks for the smoke run.
    if (pathname === '/v1/entries/CVE-1900-0500') return new Response('boom', { status: 500 });
    if (pathname === '/v1/sitemap.xml')
      return new Response(SITEMAP, { headers: { 'Content-Type': 'application/xml' } });
    return fixtureApi(request);
  },
} satisfies ExportedHandler;
