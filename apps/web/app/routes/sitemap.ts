import { getData } from '../data/data.server';
import type { Route } from './+types/sitemap';

const notFound = () =>
  new Response('Not found', {
    status: 404,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
  });

/** `/sitemap.xml`: passes ti-api's sitemap through in api mode. Anything else is a plain 404. */
export async function loader({ request }: Route.LoaderArgs) {
  const site = getData(request);
  if (site.mode !== 'api') return notFound();
  let upstream: Response | null;
  try {
    upstream = await site.sitemap();
  } catch {
    return notFound();
  }
  if (!upstream) return notFound();
  return new Response(upstream.body, {
    status: 200,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
