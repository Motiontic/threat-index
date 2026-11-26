import { logEvent, REQUEST_ID_HEADER, requestIdFrom } from '@ti/core/log';
import type { MiddlewareHandler } from 'hono';
import { routePath } from 'hono/route';
import type { AppEnv } from './env';
import { currentUserId } from './auth';
import { mutableHeaders } from './headers';

/**
 * First middleware: a request id (kept when well formed, else fresh) on the context and every response,
 * and one `request` log line after the handler. The route is the Hono pattern, never the raw path or query.
 */
export const requestContext: MiddlewareHandler<AppEnv> = async (c, next) => {
  const requestId = requestIdFrom(c.req.header(REQUEST_ID_HEADER) ?? null);
  c.set('requestId', requestId);
  const started = Date.now();
  await next();
  mutableHeaders(c).set(REQUEST_ID_HEADER, requestId);
  const userId = currentUserId(c);
  let route = 'unknown';
  try {
    route = routePath(c, -1);
  } catch {
    // keep 'unknown'
  }
  logEvent('info', 'request', {
    requestId,
    method: c.req.method,
    route,
    status: c.res.status,
    ms: Date.now() - started,
    ...(userId ? { userId } : {}),
    ...(c.get('limited') ? { limited: true } : {}),
  });
};
