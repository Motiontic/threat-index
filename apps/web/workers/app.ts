import { env } from 'cloudflare:workers';
import { ipKey } from '@ti/core/edge';
import { logEvent, REQUEST_ID_HEADER } from '@ti/core/log';
import { createRequestHandler } from 'react-router';
import { currentMode } from '../app/data/data.server';
import {
  applyMissingBaseHeaders,
  RATE_LIMIT_RETRY_AFTER,
  rateLimitedResponse,
  secureRedirect,
  shouldNoindex,
} from '../app/lib/security.server';
import { workersDevRedirect } from '../app/lib/site.server';

const requestHandler = createRequestHandler(
  () => import('virtual:react-router/server-build'),
  import.meta.env.MODE,
);

/** Per-IP page limit. Fails open: a missing binding or a throwing limit() lets the request through. */
async function overLimit(request: Request): Promise<boolean> {
  const ip = request.headers.get('cf-connecting-ip');
  if (!ip || !env.RL_PAGES) return false;
  try {
    return !(await env.RL_PAGES.limit({ key: `ip:${ipKey(ip)}` })).success;
  } catch {
    logEvent('warn', 'rate_limit_unavailable', { reason: 'limit_threw' });
    return false;
  }
}

/** `/mcp`, `/mcp/...` and the OAuth protected-resource metadata paths belong to ti-mcp. `/mcpx` and `/mcp-docs` do not. */
function isMcpPath(pathname: string): boolean {
  const PRM = '/.well-known/oauth-protected-resource';
  return pathname === '/mcp' || pathname.startsWith('/mcp/') || pathname === PRM || pathname.startsWith(`${PRM}/`);
}

/**
 * Hands an MCP request to ti-mcp (the `MCP` service binding), or answers 404 when MCP is off (`MCP_ENABLED` is
 * not "1"). The response comes back unchanged: no page headers and no noindex logic, because ti-mcp sets its own.
 * The request goes without its `Cookie` header, and without any `x-ti-mcp-*` header a visitor sent, so nothing a
 * visitor sends can pose as the signed identity ti-mcp gives ti-api, and no session cookie reaches ti-mcp.
 */
async function forwardToMcp(request: Request, requestId: string): Promise<Response> {
  if (env.MCP_ENABLED !== '1' || !env.MCP) {
    const headers = new Headers({
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      [REQUEST_ID_HEADER]: requestId,
    });
    applyMissingBaseHeaders(headers);
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers });
  }
  const headers = new Headers(request.headers);
  headers.delete('cookie');
  for (const name of [...headers.keys()]) if (name.startsWith('x-ti-mcp-')) headers.delete(name);
  return env.MCP.fetch(new Request(request, { headers }));
}

export default {
  async fetch(request) {
    const started = Date.now();
    // Always a fresh id: a visitor's x-request-id is replaced, so it cannot forge a log trail.
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);
    // MCP comes first: before the redirect and the page limit, which are for pages. Not counted by RL_PAGES.
    if (isMcpPath(url.pathname)) {
      const forwarded = await forwardToMcp(request, requestId);
      logEvent('info', 'request', {
        requestId,
        method: request.method,
        route: 'mcp',
        status: forwarded.status,
        ms: Date.now() - started,
      });
      return forwarded;
    }
    let response: Response;
    const toSite = workersDevRedirect(request, { tiEnv: env.TI_ENV, siteOrigin: env.SITE_ORIGIN });
    if (toSite) {
      response = toSite;
    } else if (await overLimit(request)) {
      response = rateLimitedResponse(url.pathname.endsWith('.data'));
    } else {
      const headers = new Headers(request.headers);
      headers.set(REQUEST_ID_HEADER, requestId);
      const handled = await requestHandler(new Request(request, { headers }));
      // Loader redirects never reach `handleRequest`; give them the document headers here.
      response = secureRedirect(handled, {
        dev: import.meta.env.DEV,
        noindex: shouldNoindex({ mode: currentMode(), tiEnv: env.TI_ENV, status: handled.status }),
      });
    }
    // Some responses (a cached or fetched one) have immutable headers: copy once if so.
    try {
      response.headers.set(REQUEST_ID_HEADER, requestId);
    } catch {
      response = new Response(response.body, response);
      response.headers.set(REQUEST_ID_HEADER, requestId);
    }
    applyMissingBaseHeaders(response.headers);
    if (response.status === 429 && !response.headers.has('Retry-After'))
      response.headers.set('Retry-After', RATE_LIMIT_RETRY_AFTER);
    logEvent('info', 'request', {
      requestId,
      method: request.method,
      path: url.pathname.slice(0, 120),
      status: response.status,
      ms: Date.now() - started,
    });
    return response;
  },
} satisfies ExportedHandler<Env>;
