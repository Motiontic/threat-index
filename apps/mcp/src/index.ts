import { logEvent, REQUEST_ID_HEADER } from '@ti/core/log';
import { API_SECURITY_HEADERS } from '@ti/core/security-headers';
import type { Env } from './env';

export { McpTask } from './tasks/mcp-task';

/** `not_ready`: an application error code, outside the reserved JSON-RPC range (-32768 to -32000). */
const NOT_READY = { jsonrpc: '2.0', id: null, error: { code: -31001, message: 'not_ready' } };

function respond(body: unknown, status: number, requestId: string, extra: Record<string, string> = {}) {
  const headers = new Headers({
    ...API_SECURITY_HEADERS,
    'Cache-Control': 'no-store',
    [REQUEST_ID_HEADER]: requestId,
    ...extra,
  });
  if (body === null) return new Response(null, { status, headers });
  headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify(body), { status, headers });
}

/**
 * ti-mcp. For now `POST /mcp` answers "not ready": the protocol, OAuth checks and tools come in their own
 * changes. Only the shape is fixed here: which paths exist and what every response carries.
 */
export default {
  async fetch(request, _env, _ctx) {
    const requestId = crypto.randomUUID();
    const started = Date.now();
    const { pathname } = new URL(request.url);
    let route = 'unknown';
    let res: Response;
    if (pathname === '/mcp') {
      route = '/mcp';
      res =
        request.method === 'POST'
          ? respond(NOT_READY, 503, requestId)
          : respond({ error: 'method_not_allowed' }, 405, requestId, { Allow: 'POST' });
    } else {
      // /.well-known/oauth-protected-resource/mcp and /mcp/server-card land later; 404 until then.
      res = respond({ error: 'not_found' }, 404, requestId);
    }
    logEvent('info', 'request', {
      requestId,
      method: request.method,
      route,
      status: res.status,
      ms: Date.now() - started,
    });
    return res;
  },
} satisfies ExportedHandler<Env>;
