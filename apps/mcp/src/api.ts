import { type McpIdentity, signMcpAssertion } from '@ti/core/mcp-user';
import type { Env } from './env';

const API_ORIGIN = 'https://ti-api.internal';

export interface ApiCall {
  method: string;
  /** Path and query, starting with a single "/". */
  path: string;
  /** JSON text, or none. */
  body?: string | null;
  identity: McpIdentity;
  requestId: string;
  /** Aborts the call: client disconnect, cancellation or the run-time limit. */
  signal?: AbortSignal;
}

/**
 * The only place ti-mcp calls ti-api, and the only file in apps/mcp that calls `fetch` (scripts/check-no-fetch.mjs
 * keeps it so). It builds a fresh request: nothing from the client's request is copied, and the user's OAuth
 * token never leaves this Worker. ti-api gets a signed assertion bound to this one request instead.
 */
export async function callApi(env: Env, call: ApiCall): Promise<Response> {
  const secret = env.MCP_HMAC_SECRET;
  if (!secret) throw new Error('MCP_HMAC_SECRET is not configured');
  if (!/^\/(?!\/)/.test(call.path)) throw new Error('callApi: path must start with a single "/"');
  const url = new URL(call.path, API_ORIGIN);
  if (url.origin !== API_ORIGIN) throw new Error('callApi: path left the API origin');
  const method = call.method.toUpperCase();
  const bodyText = call.body ?? null;
  const bodyBytes = bodyText === null ? null : new TextEncoder().encode(bodyText);

  const assertion = await signMcpAssertion(
    secret,
    call.identity,
    {
      requestId: call.requestId,
      method,
      pathWithQuery: url.pathname + url.search,
      body: bodyBytes ? (bodyBytes.buffer as ArrayBuffer) : null,
    },
    Math.floor(Date.now() / 1000),
  );
  const headers = new Headers({ accept: 'application/json', 'x-request-id': call.requestId, ...assertion });
  if (bodyText !== null) headers.set('content-type', 'application/json');
  return env.API.fetch(
    new Request(url, {
      method,
      headers,
      ...(bodyText !== null ? { body: bodyText } : {}),
      ...(call.signal ? { signal: call.signal } : {}),
    }),
  );
}
