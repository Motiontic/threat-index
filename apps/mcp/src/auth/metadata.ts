import { requestIdFrom } from '@ti/core/log';
import { allowedOrigins, checkOrigin, preflight } from '../http/origin';
import { finish, json } from '../http/respond';
import { limitAnon } from '../rate-limit';
import { logRequest } from '../log';
import type { Env } from '../env';

/** The protected-resource metadata document (RFC 9728), at the path-aware URL only. */
export async function handleMetadata(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const started = Date.now();
  const requestId = requestIdFrom(request.headers.get('x-request-id'));
  const origin = checkOrigin(request, allowedOrigins(env.MCP_ALLOWED_ORIGINS));
  const cors = origin.ok ? origin.origin : null;
  const done = (res: Response, outcome: 'ok' | 'limited' | 'rejected') => {
    logRequest({ requestId, route: 'metadata', status: res.status, outcome, ms: Date.now() - started });
    return finish(res, { requestId, corsOrigin: cors });
  };
  if (await limitAnon(env, request)) return done(json({ error: 'rate_limited', requestId }, 429, { 'Retry-After': '60' }), 'limited');
  if (request.method === 'OPTIONS') {
    if (origin.ok && origin.origin) return done(preflight(origin.origin, 'GET'), 'ok');
    return done(json({ error: origin.ok ? 'method_not_allowed' : 'origin_not_allowed', requestId }, origin.ok ? 405 : 403, origin.ok ? { Allow: 'GET, HEAD' } : {}), 'rejected');
  }
  if (request.method !== 'GET' && request.method !== 'HEAD')
    return done(json({ error: 'method_not_allowed', requestId }, 405, { Allow: 'GET, HEAD' }), 'rejected');
  const body = JSON.stringify({
    resource: env.MCP_RESOURCE_URL,
    authorization_servers: [env.CLERK_ISSUER],
    scopes_supported: ['mti:read', 'mti:watch'],
    bearer_methods_supported: ['header'],
  });
  return done(
    new Response(request.method === 'HEAD' ? null : body, {
      status: 200,
      headers: { 'content-type': 'application/json', 'Cache-Control': 'public, max-age=3600' },
    }),
    'ok',
  );
}
