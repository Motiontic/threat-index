import { REQUEST_ID_HEADER } from '@ti/core/log';
import { API_SECURITY_HEADERS } from '@ti/core/security-headers';
import { corsHeaders } from './origin';

export function json(body: unknown, status: number, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

/** Every response leaves through here: security headers, request id, no-store, no session id. */
export function finish(res: Response, opts: { requestId: string; corsOrigin?: string | null }): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(API_SECURITY_HEADERS)) headers.set(k, v);
  headers.set(REQUEST_ID_HEADER, opts.requestId);
  if (!headers.has('cache-control')) headers.set('Cache-Control', 'no-store');
  headers.delete('mcp-session-id');
  if (opts.corsOrigin) for (const [k, v] of Object.entries(corsHeaders(opts.corsOrigin))) headers.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}
