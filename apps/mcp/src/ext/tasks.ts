import { CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/server/validators/cf-worker';
import { logEvent } from '@ti/core/log';
import type { McpIdentity } from '@ti/core/mcp-user';
import type { Env } from '../env';
import { rpcError } from '../http/errors';
import { json } from '../http/respond';
import { findBadText } from '../input';
import type { Outcome, RequestLog } from '../log';
import { taskStub, withCursor } from '../tasks/client';
import { TASK_ID_RE } from '../tasks/ids';
import type { CreateResult, TaskKind, TaskView } from '../tasks/mcp-task';
import { TOOLS, type ToolName } from '../tools';
import { failureResult, type ToolAnswer, type ToolDef, type ToolErrorCode } from '../tools/shared';
import { TRUST_META } from '../trust';

export const TASKS_EXTENSION = 'io.modelcontextprotocol/tasks';
export const TASK_METHODS = new Set(['tasks/get', 'tasks/update', 'tasks/cancel']);
const MAX_INLINE = 1000;
const REVISION = '2026-07-28';

/** The entry `server/discover` lists under `capabilities.extensions`. */
export const capability = (): Record<string, Record<string, string>> => ({ [TASKS_EXTENSION]: {} });

/** Extension point kept from the skeleton: tasks need no registration, the pipeline answers them itself. */
export function register(): void {}

const obj = (v: unknown): Record<string, unknown> | null =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/** True when this request's own `_meta` declares the Tasks extension. */
export function declaresTasks(params: Record<string, unknown>): boolean {
  const caps = obj(obj(params._meta)?.[CLIENT_CAPABILITIES_META_KEY]);
  return obj(obj(caps?.extensions)?.[TASKS_EXTENSION]) !== null;
}

export function missingCapability(requestId: string, id: string | number | null): Response {
  return rpcError(400, -32021, requestId, id, {
    requiredCapabilities: { extensions: { [TASKS_EXTENSION]: {} } },
  });
}

export interface TaskRequest {
  env: Env;
  identity: McpIdentity;
  /** The access token's expiry, in seconds. */
  tokenExpiresAt: number;
  requestId: string;
  request: Request;
  msg: Record<string, unknown>;
  params: Record<string, unknown>;
  era: 'modern' | 'legacy';
  /** The decoded `Mcp-Name` header: whether it was sent, and its value (null when it could not be decoded). */
  mcpName: { present: boolean; value: string | null };
  now?: () => number;
}
export interface Intercepted {
  res: Response;
  outcome: Outcome;
  extra: Partial<RequestLog>;
}

const iso = (ms: number) => new Date(ms).toISOString();
const validator = new CfWorkerJsonSchemaValidator({ draft: '2020-12' });

function ok(id: string | number | null, result: Record<string, unknown>): Response {
  return json({ jsonrpc: '2.0', id, result }, 200);
}

function taskAnswer(t: TaskView): Record<string, unknown> {
  return {
    resultType: 'task',
    taskId: t.taskId,
    status: t.status,
    ...(t.statusMessage ? { statusMessage: t.statusMessage } : {}),
    createdAt: iso(t.createdAt),
    lastUpdatedAt: iso(t.lastUpdatedAt),
    ttlMs: t.ttlMs,
    pollIntervalMs: t.pollIntervalMs,
  };
}

/**
 * Whether this request is one the pipeline answers itself, and what kind. A notification (no `id`) and anything
 * that is not JSON-RPC 2.0 is never taken: the SDK path answers those as it always has.
 */
function classify(
  c: TaskRequest,
): { kind: 'tasks' } | { kind: 'tool'; name: ToolName; args: Record<string, unknown> } | null {
  if (c.msg.jsonrpc !== '2.0') return null;
  if (typeof c.msg.id !== 'string' && typeof c.msg.id !== 'number') return null;
  const method = c.msg.method;
  if (typeof method === 'string' && TASK_METHODS.has(method)) return { kind: 'tasks' };
  if (method !== 'tools/call') return null;
  const name = c.params.name;
  const args = obj(c.params.arguments) ?? {};
  if (name === 'mti_deep_query' && typeof args.cursor !== 'string' && TOOLS[name]?.enabled)
    return { kind: 'tool', name, args };
  if (
    name === 'mti_check_packages' &&
    c.era === 'modern' &&
    obj(c.params._meta)?.[PROTOCOL_VERSION_META_KEY] === REVISION &&
    declaresTasks(c.params) &&
    Array.isArray(args.packages) &&
    args.packages.length > MAX_INLINE &&
    TOOLS[name]?.enabled
  )
    return { kind: 'tool', name, args };
  return null;
}

/** The checks the SDK makes on a modern request, repeated here because the SDK never sees this one. */
function headerMismatch(c: TaskRequest): boolean {
  const meta = obj(c.params._meta);
  const revision = meta?.[PROTOCOL_VERSION_META_KEY];
  const h = c.request.headers;
  if (h.get('mcp-protocol-version')?.trim() !== revision) return true;
  if (h.get('mcp-method')?.trim() !== c.msg.method) return true;
  // A taskId that is not a string is answered -32602 by the handler, not refused here.
  if (c.msg.method !== 'tools/call' && typeof c.params.taskId !== 'string') return false;
  const want = c.msg.method === 'tools/call' ? c.params.name : c.params.taskId;
  return !(typeof want === 'string' && c.mcpName.present && c.mcpName.value === want);
}

/**
 * Answers the requests the SDK cannot: `tasks/get`, `tasks/update`, `tasks/cancel`, and the `tools/call` that
 * becomes a task. Null for everything else, which stays on the SDK path. It runs after every other check
 * (size caps, sign-in, scope, origin) and only 2026-07-28 requests are served; a 2025-era request for either
 * gets -32021.
 */
export async function interceptTask(c: TaskRequest): Promise<Intercepted | null> {
  const what = classify(c);
  if (!what) return null;
  const id = c.msg.id as string | number;
  const rpc = (res: Response, code: number): Intercepted => ({ res, outcome: 'rpc_error', extra: { code } });

  const current = c.era === 'modern' && obj(c.params._meta)?.[PROTOCOL_VERSION_META_KEY] === REVISION;
  if (c.era === 'modern' && headerMismatch(c)) return rpc(rpcError(400, -32020, c.requestId, id), -32020);
  if (!current || !declaresTasks(c.params)) return rpc(missingCapability(c.requestId, id), -32021);
  if (what.kind === 'tool') return startTask(c, what.name, what.args, id);
  return handleTaskMethod(c, id);
}

async function handleTaskMethod(c: TaskRequest, id: string | number | null): Promise<Intercepted> {
  const rpc = (res: Response, code: number): Intercepted => ({ res, outcome: 'rpc_error', extra: { code } });
  const taskId = c.params.taskId;
  // The same answer for a malformed, unknown, expired or another user's ID.
  const unknown = () => rpc(rpcError(200, -32602, c.requestId, id, { field: 'taskId' }), -32602);
  if (typeof taskId !== 'string' || !TASK_ID_RE.test(taskId)) return unknown();
  const sub = c.identity.sub;
  const stub = taskStub(c.env, sub);
  try {
    switch (c.msg.method) {
      case 'tasks/update': {
        // Our tasks never ask for input, so there is nothing to answer: the keys are ignored.
        return (await stub.exists(sub, taskId))
          ? { res: ok(id, { resultType: 'complete' }), outcome: 'ok', extra: {} }
          : unknown();
      }
      case 'tasks/cancel': {
        const r = await stub.cancel(sub, taskId);
        return r.found ? { res: ok(id, { resultType: 'complete' }), outcome: 'ok', extra: {} } : unknown();
      }
      default: {
        const g = await stub.get(sub, taskId);
        if (!g.found || !g.task) return unknown();
        const base = { resultType: 'complete', ...taskAnswer(g.task) };
        base.resultType = 'complete';
        if (g.failed)
          return {
            res: ok(id, {
              ...base,
              error: { code: -32603, message: 'Internal error', data: { requestId: g.requestId } },
            }),
            outcome: 'ok',
            extra: {},
          };
        if (g.outcome?.kind === 'tool_error') {
          const result = failureResult(g.requestId ?? c.requestId, {
            ok: false,
            code: g.outcome.code as ToolErrorCode,
            ...(g.outcome.retryAfter ? { retryAfter: g.outcome.retryAfter } : {}),
            ...(g.outcome.note ? { note: g.outcome.note } : {}),
            ...(g.outcome.field ? { field: g.outcome.field } : {}),
          });
          return {
            res: ok(id, { ...base, result }),
            outcome: 'tool_error',
            extra: { code: g.outcome.code },
          };
        }
        if (g.page) {
          const kind: TaskKind = g.task.kind;
          const data = await withCursor(c.env, kind, sub, taskId, g.page);
          const result = {
            structuredContent: data,
            content: [{ type: 'text', text: JSON.stringify(data) }],
            _meta: { ...TRUST_META },
          };
          return { res: ok(id, { ...base, result }), outcome: 'ok', extra: {} };
        }
        return { res: ok(id, base), outcome: 'ok', extra: {} };
      }
    }
  } catch (e) {
    logEvent('error', 'mcp_task_error', {
      method: String(c.msg.method),
      error: e instanceof Error ? e.name : 'unknown',
    });
    return rpc(rpcError(500, -32603, c.requestId, id), -32603);
  }
}

/** A tool-error result for a request answered by the pipeline, with the stats the log line carries. */
function toolFailure(
  c: TaskRequest,
  id: string | number | null,
  name: string,
  a: Extract<ToolAnswer, { ok: false }>,
): Intercepted {
  return {
    res: ok(id, failureResult(c.requestId, a)),
    outcome: 'tool_error',
    extra: { tool: name, code: a.code },
  };
}

async function startTask(
  c: TaskRequest,
  name: ToolName,
  args: Record<string, unknown>,
  id: string | number | null,
): Promise<Intercepted> {
  const def = TOOLS[name] as ToolDef<never>;
  const fail = (a: Extract<ToolAnswer, { ok: false }>) => toolFailure(c, id, name, a);

  // The same checks the SDK path makes, in the same order: off-switch, schema, hidden characters.
  let off: string | null | undefined;
  try {
    off = await c.env.SETTINGS.get(`mcp:tool:${name}:off`, { cacheTtl: 60 });
  } catch {
    logEvent('warn', 'mcp_tool_switch_error', { tool: name });
  }
  if (off !== null && off !== undefined) return fail({ ok: false, code: 'tool_off' });
  if (!validator.getValidator(def.inputSchema as never)(args).valid)
    return fail({ ok: false, code: 'invalid_argument', field: 'input' });
  // Starting a deep query needs a template (a call with only a cursor never gets here). Checked before a slot is reserved.
  if (name === 'mti_deep_query' && typeof args.template !== 'string')
    return fail({ ok: false, code: 'invalid_argument', field: 'template' });
  const bad = findBadText(args);
  if (bad) return fail({ ok: false, code: 'invalid_argument', field: bad, problem: 'bad_characters' });

  const stub = taskStub(c.env, c.identity.sub);
  const tokenExp = c.tokenExpiresAt * 1000;
  let made: CreateResult;
  try {
    made =
      name === 'mti_check_packages'
        ? await stub.createCheck(c.identity, tokenExp, args.packages as unknown[])
        : await stub.startDeepQuery(c.identity, tokenExp, {
            template: args.template as string,
            params: (args.params ?? {}) as Record<string, string>,
          });
  } catch {
    return fail({ ok: false, code: 'internal' });
  }
  if (!made.ok)
    return fail({
      ok: false,
      code: made.code as ToolErrorCode,
      ...(made.retryAfter ? { retryAfter: made.retryAfter } : {}),
      ...(made.field ? { field: made.field } : {}),
    });
  const nIn = Array.isArray(args.packages) ? args.packages.length : undefined;
  return {
    res: ok(id, taskAnswer(made.task)),
    outcome: 'ok',
    extra: { tool: name, ...(nIn !== undefined ? { nIn } : {}) },
  };
}
