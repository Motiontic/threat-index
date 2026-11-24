import { siteOrigin } from '../lib/site.server';
import type { Route } from './+types/robots';

/** `/robots.txt`: allow everything and point at the sitemap on the configured site URL, never the request host. */
export function loader({ request }: Route.LoaderArgs) {
  const body = `User-agent: *\nAllow: /\n\nSitemap: ${siteOrigin(request)}/sitemap.xml\n`;
  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
