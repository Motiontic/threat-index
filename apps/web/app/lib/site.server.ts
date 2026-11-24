// The site's canonical origin. Canonical links, Open Graph URLs, JSON-LD and robots.txt use the configured
// `SITE_ORIGIN` (a var set at deploy from TI_APP_URL / TI_APP_URL_STAGING), never the request host, so a page
// reached on workers.dev still points at the real address. Without one (local runs) the request origin is used.
import { env } from 'cloudflare:workers';

/** The origin of a configured site URL: `https:` (or `http:` for localhost) only; anything else is "not set". */
export function parseSiteOrigin(value: string | undefined | null): string | null {
  const text = (value ?? '').trim();
  if (!text) return null;
  try {
    const u = new URL(text);
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) return null;
    return u.origin;
  } catch {
    return null;
  }
}

/** The origin to put in a canonical URL: the configured one, else the request's own. */
export function canonicalOrigin(request: Request, configured: string | undefined | null): string {
  return parseSiteOrigin(configured) ?? new URL(request.url).origin;
}

/** What loaders call. */
export function siteOrigin(request: Request): string {
  return canonicalOrigin(request, env.SITE_ORIGIN);
}

/**
 * Production only: a page request on the Worker's workers.dev host goes (301) to the same path and query on the
 * configured site URL. Staging, an unset or unusable site URL, other hosts and non-page requests never redirect.
 */
export function workersDevRedirect(
  request: Request,
  config: { tiEnv: string | undefined; siteOrigin: string | undefined | null },
): Response | null {
  if (config.tiEnv !== 'production') return null;
  const site = parseSiteOrigin(config.siteOrigin);
  if (!site) return null;
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  const url = new URL(request.url);
  if (!url.hostname.endsWith('.workers.dev')) return null;
  if (url.pathname.startsWith('/assets/') || url.pathname.endsWith('.data')) return null;
  // Set pathname/search on a copy of the site URL. Resolving the path as a relative reference would let
  // '//evil.com/x' replace the host.
  const target = new URL(site);
  target.pathname = url.pathname;
  target.search = url.search;
  if (target.origin !== new URL(site).origin) return null;
  return new Response(null, { status: 301, headers: { Location: target.toString() } });
}
