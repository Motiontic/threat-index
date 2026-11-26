import { requestIdFrom } from '@ti/core/log';
import { handleMetadata } from './auth/metadata';
import { handleCard } from './card';
import type { Env } from './env';
import { APP_CODES, rpcError } from './http/errors';
import { finish, json } from './http/respond';
import { logRequest } from './log';
import { handleMcp } from './mcp';

export { McpTask } from './tasks/mcp-task';

/** ti-mcp: routes by exact path. Every response leaves through `finish`. */
export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch {
      // Whatever went wrong, the caller gets a JSON-RPC error with the usual headers, not a bare error page.
      const requestId = requestIdFrom(request.headers.get('x-request-id'));
      try {
        logRequest({ requestId, route: 'mcp', status: 500, outcome: 'rpc_error', code: -32603, ms: 0 });
      } catch {
        // logging must not hide the answer
      }
      return finish(rpcError(500, -32603, requestId), { requestId });
    }
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const { pathname } = new URL(request.url);
  switch (pathname) {
    case '/mcp':
      return handleMcp(request, env, ctx);
    case '/mcp/server-card':
      return handleCard(request, env, ctx);
    case '/.well-known/oauth-protected-resource/mcp':
      return handleMetadata(request, env, ctx);
    default: {
      const requestId = requestIdFrom(request.headers.get('x-request-id'));
      logRequest({ requestId, route: 'mcp', status: 404, outcome: 'rejected', code: 'not_found', ms: 0 });
      return finish(json({ error: 'not_found', requestId }, 404), { requestId });
    }
  }
}
