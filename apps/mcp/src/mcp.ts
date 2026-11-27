import {
  createMcpHandler,
  isJsonContentType,
  isLegacyRequest,
  readRequestBody,
  TRACEPARENT_META_KEY,
} from '@modelcontextprotocol/server';
import { logEvent, requestIdFrom } from '@ti/core/log';
import type { McpIdentity } from '@ti/core/mcp-user';
import { type AuthFailure, challenge, metadataUrl } from './auth/challenge';
import { bearerFrom } from './auth/token';
import { verifyAccessToken } from './auth/verify';
import { checkConfig, MAX_RUN_MS } from './config';
import { openCursor } from './cursor';
import type { Env } from './env';
import { interceptTask } from './ext/tasks';
import {
  bodyLimitFor,
  bodyOverCap,
  elementCount,
  headersTooLarge,
  jsonDepthOk,
  MAX_CHECK_INPUT_ELEMENTS,
  MAX_JSON_DEPTH,
  MAX_TOOL_INPUT_ELEMENTS,
} from './http/body';
import { APP_CODES, rpcError } from './http/errors';
import { normaliseResponse, type SeenInfo } from './http/normalise';
import { allowedOrigins, checkOrigin, preflight } from './http/origin';
import { finish, json } from './http/respond';
import { logRequest, type Outcome, type RequestLog } from './log';
import { limitAnon } from './rate-limit';
import { buildServer, type CallStats } from './server';
import { taskExists } from './tasks/client';
import { TOOL_ORDER, type ToolName } from './tools';
import { toolsHash } from './tools-hash';

const TRACEPARENT = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;
const KNOWN_METHODS = new Set([
  'initialize',
  'notifications/initialized',
  'notifications/cancelled',
  'ping',
  'server/discover',
  'tools/list',
  'tools/call',
  'resources/list',
  'resources/templates/list',
  'resources/read',
  'resources/directory/read',
  'skills/list',
  'skills/get',
  'prompts/list',
  'completion/complete',
  'logging/setLevel',
  'subscriptions/listen',
  'tasks/get',
  'tasks/update',
  'tasks/cancel',
]);
const CELL = /^[A-Za-z0-9 _.:-]{1,60}$/;

/** An `Mcp-Name` value is plain text or `=?base64?…?=` (UTF-8). Null when it cannot be decoded. */
function decodeMcpName(raw: string): string | null {
  const m = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/.exec(raw);
  if (!m) return raw;
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(
      Uint8Array.from(atob(m[1] as string), (c) => c.charCodeAt(0)),
    );
  } catch {
    return null;
  }
}

export async function handleMcp(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const started = Date.now();
  const requestId = requestIdFrom(request.headers.get('x-request-id'));
  const log: Partial<RequestLog> = {};
  let corsOrigin: string | null = null;

  const send = (res: Response, outcome: Outcome, extra: Partial<RequestLog> = {}): Response => {
    logRequest({
      requestId,
      route: 'mcp',
      status: res.status,
      outcome,
      ms: Date.now() - started,
      ...log,
      ...extra,
    });
    return finish(res, { requestId, corsOrigin });
  };
  const refuse = (
    status: number,
    code: number,
    outcome: Outcome = 'rejected',
    headers: Record<string, string> = {},
    extra: Partial<RequestLog> = {},
  ) => send(rpcError(status, code, requestId, null, {}, headers), outcome, { code, ...extra });

  // 0. Config.
  const bad = checkConfig(env);
  if (bad.length) {
    for (const name of bad) logEvent('error', 'mcp_bad_config', { variable: name });
    return send(rpcError(503, APP_CODES.unavailable, requestId), 'rejected', { code: APP_CODES.unavailable });
  }

  // 1. Method.
  const origins = allowedOrigins(env.MCP_ALLOWED_ORIGINS);
  const origin = checkOrigin(request, origins);
  if (request.method === 'OPTIONS') {
    if (!origin.ok) return refuse(403, APP_CODES.origin_not_allowed);
    if (!origin.origin)
      return send(json({ error: 'method_not_allowed', requestId }, 405, { Allow: 'POST' }), 'rejected', {
        code: 'method',
      });
    corsOrigin = origin.origin;
    if (await limitAnon(env, request))
      return send(
        rpcError(429, APP_CODES.rate_limited, requestId, null, {}, { 'Retry-After': '60' }),
        'limited',
        { code: APP_CODES.rate_limited },
      );
    return send(preflight(origin.origin, 'POST'), 'ok');
  }
  if (request.method !== 'POST') {
    if (origin.ok) corsOrigin = origin.origin;
    return send(json({ error: 'method_not_allowed', requestId }, 405, { Allow: 'POST' }), 'rejected', {
      code: 'method',
    });
  }

  // 2. Origin.
  if (!origin.ok) return refuse(403, APP_CODES.origin_not_allowed);
  corsOrigin = origin.origin;

  // 3. Header size.
  if (headersTooLarge(request.headers)) return refuse(431, APP_CODES.headers_too_large);

  // 4. Token. The body of a request without a valid token is never read.
  const bearer = bearerFrom(request);
  let failure: AuthFailure | null = null;
  let identity: McpIdentity | null = null;
  let expiresAt = 0;
  if (bearer.kind === 'none') failure = { kind: 'none' };
  else if (bearer.kind === 'malformed') failure = { kind: 'malformed' };
  else {
    const v = await verifyAccessToken(
      bearer.token,
      { issuer: env.CLERK_ISSUER, resource: env.MCP_RESOURCE_URL },
      undefined,
      ctx,
    );
    if (v.ok) {
      identity = v.identity;
      expiresAt = v.expiresAt;
    } else if (v.reason === 'unavailable') {
      return send(challenge({ kind: 'unavailable' }, env.MCP_RESOURCE_URL, requestId), 'auth', {
        authReason: 'unavailable',
      });
    } else failure = { kind: 'reason', reason: v.reason };
  }
  if (failure || !identity) {
    const reason = failure?.kind === 'reason' ? failure.reason : failure?.kind;
    if (await limitAnon(env, request))
      return send(
        rpcError(429, APP_CODES.rate_limited, requestId, null, {}, { 'Retry-After': '60' }),
        'limited',
        { code: APP_CODES.rate_limited, authReason: reason },
      );
    return send(challenge(failure as AuthFailure, env.MCP_RESOURCE_URL, requestId), 'auth', {
      authReason: reason,
    });
  }
  if (!identity.scopes.includes('mti:read'))
    return send(challenge({ kind: 'scope' }, env.MCP_RESOURCE_URL, requestId), 'auth', {
      authReason: 'insufficient_scope',
    });

  // 5. Per-user limit.
  if (env.RL_MCP) {
    let ok = true;
    try {
      ok = (await env.RL_MCP.limit({ key: `u:${identity.sub}` })).success;
    } catch {
      logEvent('warn', 'mcp_limiter_error', { limiter: 'user' });
    }
    if (!ok) return refuse(429, APP_CODES.rate_limited, 'limited', { 'Retry-After': '60' });
  }

  // 6. Content-Type.
  if (!isJsonContentType(request.headers.get('content-type')))
    return refuse(415, APP_CODES.unsupported_media_type);

  // 7. Body.
  let text: string;
  try {
    const body = await readRequestBody(request, bodyLimitFor(request.headers));
    if (body.tooLarge) return refuse(413, APP_CODES.body_too_large);
    text = body.text;
  } catch {
    return refuse(400, APP_CODES.bad_request);
  }

  // 8. JSON.
  if (!jsonDepthOk(text, MAX_JSON_DEPTH)) return refuse(400, APP_CODES.json_too_deep);
  let parsed: unknown;
  try {
    if (text.trim() === '') throw new Error('empty');
    parsed = JSON.parse(text);
  } catch {
    return refuse(400, -32700);
  }
  if (Array.isArray(parsed)) return refuse(400, -32600);

  // 9. Pre-dispatch checks on tools/call.
  const msg = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  const params = msg.params && typeof msg.params === 'object' ? (msg.params as Record<string, unknown>) : {};
  const method = typeof msg.method === 'string' && KNOWN_METHODS.has(msg.method) ? msg.method : 'other';
  log.method = method;
  if (bodyOverCap(text, method === 'tools/call' && params.name === 'mti_check_packages'))
    return refuse(413, APP_CODES.body_too_large);
  {
    // The SDK's own limit is the large one, for the one tool that needs it; every other request keeps the small one.
    const isCheck = method === 'tools/call' && params.name === 'mti_check_packages';
    const counted = method === 'tools/call' ? params.arguments : params;
    const cap = isCheck ? MAX_CHECK_INPUT_ELEMENTS : MAX_TOOL_INPUT_ELEMENTS;
    if (elementCount(counted, cap) > cap) {
      const id = typeof msg.id === 'string' || typeof msg.id === 'number' ? msg.id : null;
      return send(rpcError(200, -32602, requestId, id, { field: 'input' }), 'rpc_error', { code: -32602 });
    }
  }
  if (method === 'tools/call') {
    log.tool = (TOOL_ORDER as readonly unknown[]).includes(params.name) ? (params.name as string) : 'other';
    const args =
      params.arguments && typeof params.arguments === 'object'
        ? (params.arguments as Record<string, unknown>)
        : null;
    if (args && typeof args.cursor === 'string') {
      const st =
        log.tool === 'other'
          ? null
          : await openCursor(
              [env.MCP_HMAC_SECRET, env.MCP_HMAC_SECRET_NEXT],
              log.tool as ToolName,
              args,
              args.cursor,
              identity.sub,
            );
      // A task cursor also needs its task: one that expired is refused here, like a tampered cursor.
      const taskId = st && 't' in st && typeof st.t === 'string' ? st.t : null;
      if (!st || (taskId !== null && !(await taskExists(env, identity.sub, taskId)))) {
        const id = typeof msg.id === 'string' || typeof msg.id === 'number' ? msg.id : null;
        return send(rpcError(200, -32602, requestId, id, { field: 'cursor' }), 'rpc_error', { code: -32602 });
      }
    }
  }
  const meta =
    params._meta && typeof params._meta === 'object' ? (params._meta as Record<string, unknown>) : {};
  const tp = meta[TRACEPARENT_META_KEY];
  if (typeof tp === 'string' && TRACEPARENT.test(tp)) log.traceparent = tp;

  // 10. Signal.
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(MAX_RUN_MS)]);

  // 11. SDK.
  const stats: CallStats = {};
  const deps = { env, identity, requestId, signal, stats, now: () => new Date() };
  const rejection: { cell?: string } = {};
  const handler = createMcpHandler(() => buildServer(deps), {
    legacy: 'stateless',
    responseMode: 'auto',
    onerror: (e) => {
      const cell = /Rejected inbound request \(([^)]*)\)/.exec(String(e?.message))?.[1];
      if (cell && CELL.test(cell)) rejection.cell = cell;
    },
  });
  const headers = new Headers(request.headers);
  for (const h of ['mcp-session-id', 'last-event-id', 'authorization', 'cookie']) headers.delete(h);
  // The SDK gets the client's own signal: a disconnect closes its exchange. The run-time limit reaches the
  // tools through `deps.signal` instead, so a timeout comes back as the `timeout` tool error, not an empty 499.
  const forward = new Request(request.url, { method: 'POST', headers, signal: request.signal });
  const authInfo = {
    token: 'verified',
    clientId: identity.clientId,
    scopes: identity.scopes,
    expiresAt,
    resource: new URL(env.MCP_RESOURCE_URL),
    resourceMetadataUrl: new URL(metadataUrl(env.MCP_RESOURCE_URL)),
    extra: { sub: identity.sub },
  };
  log.era = (await isLegacyRequest(forward, parsed)) ? 'legacy' : 'modern';
  // The SDK checks Mcp-Name only on modern requests. On the legacy leg, refuse a mismatch here.
  if (log.era === 'legacy' && method === 'tools/call') {
    const hdr = request.headers.get('mcp-name');
    if (hdr !== null && decodeMcpName(hdr) !== params.name) return refuse(400, -32020);
  }
  log.toolsHash = await toolsHash();

  // Requests the SDK cannot answer (MCP Tasks) are answered here; everything else goes on to the SDK.
  const nameHeader = request.headers.get('mcp-name');
  const task = await interceptTask({
    env,
    identity,
    tokenExpiresAt: expiresAt,
    requestId,
    request,
    msg,
    params,
    era: log.era,
    mcpName: { present: nameHeader !== null, value: nameHeader === null ? null : decodeMcpName(nameHeader) },
  });
  if (task) return send(task.res, task.outcome, task.extra);

  let res: Response;
  try {
    // `handler.fetch` is the SDK handler's own entry, not a network call (the no-fetch lint allows this receiver).
    res = await handler.fetch(forward, { authInfo, parsedBody: parsed } as never);
  } catch {
    return send(rpcError(500, -32603, requestId), 'rpc_error', { code: -32603 });
  }

  // 12. Answer. Every /mcp answer is no-store, whatever the SDK set.
  {
    const h = new Headers(res.headers);
    h.delete('cache-control');
    res = new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
  }
  const statsLog = (): Partial<RequestLog> => ({
    ...(stats.tool ? { tool: stats.tool } : {}),
    ...(stats.nIn !== undefined ? { nIn: stats.nIn } : {}),
    ...(stats.nOut !== undefined ? { nOut: stats.nOut } : {}),
    ...(stats.ecosystems ? { ecosystems: stats.ecosystems } : {}),
    ...(stats.toolError ? { code: stats.toolError } : {}),
  });
  const ct = res.headers.get('content-type')?.toLowerCase() ?? '';
  if (ct.startsWith('text/event-stream') && res.body) {
    const done = () => {
      logRequest({
        requestId,
        route: 'mcp',
        status: res.status,
        outcome: stats.toolError ? 'tool_error' : 'ok',
        ms: Date.now() - started,
        ...log,
        ...statsLog(),
        ...(rejection.cell ? { code: rejection.cell } : {}),
      });
    };
    const body = res.body.pipeThrough(new TransformStream({ flush: done }));
    return finish(new Response(body, { status: res.status, headers: res.headers }), {
      requestId,
      corsOrigin,
    });
  }
  const seen: SeenInfo = {};
  const out = await normaliseResponse(res, requestId, seen);
  const outcome: Outcome =
    seen.code !== undefined
      ? 'rpc_error'
      : stats.toolError || seen.toolError
        ? 'tool_error'
        : res.status >= 400
          ? 'rejected'
          : 'ok';
  return send(out, outcome, {
    ...statsLog(),
    ...(seen.code !== undefined ? { code: seen.code } : {}),
    ...(rejection.cell ? { authReason: undefined, code: seen.code ?? rejection.cell } : {}),
  });
}
