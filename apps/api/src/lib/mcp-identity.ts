import { logEvent } from '@ti/core/log';
import { MCP_HEADERS, verifyMcpAssertion } from '@ti/core/mcp-user';
import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from './env';
import { findMcpRoute } from './mcp-routes';

/** Largest body read for the signature. Real bodies are far smaller (1000 packages is ~200 KB). */
export const MAX_MCP_BODY_BYTES = 2 * 1024 * 1024;

const MCP_PREFIX = 'x-ti-mcp-';
const KNOWN = new Set<string>(Object.values(MCP_HEADERS));

/** Reads a request body once, up to a limit. Null when it is larger. */
async function readBounded(req: Request, limit: number): Promise<ArrayBuffer | null> {
  if (!req.body) return new ArrayBuffer(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out.buffer;
}

/**
 * Runs on `/v1/*` before the Clerk middleware. Turns the signed assertion `ti-mcp` sends into
 * `c.get('mcp')`, and refuses everything else a caller with MCP headers might try.
 *
 * - No `x-ti-mcp-*` header: does nothing (web and browser traffic is unchanged).
 * - An MCP header together with `Authorization` or `Cookie`: 400 `ambiguous_auth`.
 * - A bad or missing assertion: 401 `bad_mcp_assertion`. Never falls through to Clerk.
 * - A route not in `MCP_ROUTES`: 403 `not_allowed_for_mcp`. A missing scope: 403 `insufficient_scope`.
 * - A user or client on the block list: 403 `blocked`.
 */
export const mcpIdentity: MiddlewareHandler<AppEnv> = async (c, next) => {
  const headers = c.req.raw.headers;
  let hasMcpHeader = false;
  for (const name of headers.keys()) {
    if (name.startsWith(MCP_PREFIX)) {
      hasMcpHeader = true;
      break;
    }
  }
  if (!hasMcpHeader) return next();

  if (headers.has('authorization') || headers.has('cookie')) return c.json({ error: 'ambiguous_auth' }, 400);
  // Unknown x-ti-mcp-* names are not part of the contract: refuse rather than ignore.
  for (const name of headers.keys())
    if (name.startsWith(MCP_PREFIX) && !KNOWN.has(name)) return c.json({ error: 'bad_mcp_assertion' }, 401);

  const url = new URL(c.req.url);
  const body = await readBounded(c.req.raw.clone(), MAX_MCP_BODY_BYTES);
  if (body === null) return c.json({ error: 'bad_mcp_assertion' }, 401);
  const identity = await verifyMcpAssertion([c.env.MCP_HMAC_SECRET, c.env.MCP_HMAC_SECRET_NEXT], headers, {
    requestId: c.get('requestId'),
    method: c.req.method,
    pathWithQuery: url.pathname + url.search,
    body,
  });
  if (!identity) {
    logEvent('warn', 'mcp_assertion_rejected', { requestId: c.get('requestId') });
    return c.json({ error: 'bad_mcp_assertion' }, 401);
  }

  const route = findMcpRoute(c.req.method, url.pathname);
  if (!route) return c.json({ error: 'not_allowed_for_mcp' }, 403);
  if (!identity.scopes.includes(route.scope))
    return c.json({ error: 'insufficient_scope', scope: route.scope }, 403);

  const blocked = await c.env.DB_USERS.prepare(
    `SELECT 1 FROM mcp_blocks WHERE ((kind = 'user' AND id = ?1) OR (kind = 'client' AND id = ?2)) AND (expires_at IS NULL OR expires_at > ?3)`,
  )
    .bind(identity.sub, identity.clientId, new Date().toISOString())
    .first();
  if (blocked) return c.json({ error: 'blocked' }, 403);

  c.set('mcp', identity);
  return next();
};
