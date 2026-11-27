import type { McpScope } from './mcp-scopes';

/**
 * The only API routes a signed MCP identity may call, each with the scope it needs. Anything else gets
 * 403 `not_allowed_for_mcp`: admin, internal jobs, webhooks, `DELETE /v1/me`, saved searches.
 * A new API route used by MCP needs an entry here (REVIEW.md, "MCP").
 */
export interface McpRoute {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  /** Literal segments and `:param` segments. Matched against the raw path, segment by segment. */
  pattern: string;
  scope: McpScope;
}

const read = (method: McpRoute['method'], pattern: string): McpRoute => ({
  method,
  pattern,
  scope: 'mti:read',
});
const watch = (method: McpRoute['method'], pattern: string): McpRoute => ({
  method,
  pattern,
  scope: 'mti:watch',
});

export const MCP_ROUTES: readonly McpRoute[] = [
  read('GET', '/v1/search'),
  read('GET', '/v1/entries/:id'),
  read('GET', '/v1/home'),
  read('GET', '/v1/breaches'),
  read('GET', '/v1/breaches/:key'),
  read('GET', '/v1/incidents'),
  read('GET', '/v1/incidents/:source/:id'),
  read('GET', '/v1/techniques/:id'),
  read('GET', '/v1/sources'),
  read('POST', '/v1/packages/check'),
  read('POST', '/v1/deep-query'),
  read('GET', '/v1/deep-query/:id'),
  read('DELETE', '/v1/deep-query/:id'),
  read('GET', '/v1/me'),
  read('GET', '/v1/me/watch'),
  read('GET', '/v1/me/watch/packages'),
  read('GET', '/v1/me/changes'),
  watch('PATCH', '/v1/me'),
  watch('PUT', '/v1/me/watch/:id'),
  watch('DELETE', '/v1/me/watch/:id'),
  watch('PUT', '/v1/me/watch/packages/:ecosystem/:name'),
  watch('DELETE', '/v1/me/watch/packages/:ecosystem/:name'),
];

function matches(pattern: string, pathname: string): boolean {
  const want = pattern.split('/');
  const got = pathname.split('/');
  if (want.length !== got.length) return false; // strict: "/v1/me/" is not "/v1/me"
  return want.every((seg, i) => (seg.startsWith(':') ? (got[i] as string).length > 0 : seg === got[i]));
}

/** The allow-list entry for this request, or null. Exact match on the raw path: encoded look-alikes don't match. */
export function findMcpRoute(method: string, pathname: string): McpRoute | null {
  const m = method.toUpperCase();
  return MCP_ROUTES.find((r) => r.method === m && matches(r.pattern, pathname)) ?? null;
}
