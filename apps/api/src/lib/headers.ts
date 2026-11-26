import { API_SECURITY_HEADERS } from '@ti/core/security-headers';
import type { Context, MiddlewareHandler } from 'hono';
import type { AppEnv } from './env';

export { API_SECURITY_HEADERS } from '@ti/core/security-headers';

/** Response headers are immutable on some responses (a cache hit); copy once if so. */
export function mutableHeaders(c: Context<AppEnv>): Headers {
  try {
    c.res.headers.set('X-Content-Type-Options', c.res.headers.get('X-Content-Type-Options') ?? 'nosniff');
  } catch {
    c.res = new Response(c.res.body, c.res);
  }
  return c.res.headers;
}

/** Sets each header the route has not set itself (so `/unsubscribe` keeps its CSP), and no-store on errors. */
export const securityHeaders: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next();
  const headers = mutableHeaders(c);
  for (const [name, value] of Object.entries(API_SECURITY_HEADERS))
    if (!headers.has(name)) headers.set(name, value);
  if (c.res.status >= 400) headers.set('Cache-Control', 'no-store');
};
