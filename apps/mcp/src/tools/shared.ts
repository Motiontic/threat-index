import { fromJsonSchema, type McpServer, requireScopes } from '@modelcontextprotocol/server';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/server/validators/cf-worker';
import { logEvent } from '@ti/core/log';
import { callApi } from '../api';
import { findBadText, type InputProblem } from '../input';
import type { JsonSchema } from '../schema';
import type { CallDeps } from '../server';
import { TRUST_META } from '../trust';
import type { ToolName } from './index';

export type ToolErrorCode =
  | 'invalid_argument'
  | 'not_available_yet'
  | 'rate_limited'
  | 'blocked'
  | 'tool_off'
  | 'upstream_unavailable'
  | 'timeout'
  | 'too_many_tasks'
  | 'too_many_packages'
  | 'internal';
export const HINTS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;
export const MAX_STRUCTURED_CHARS = 32_000;
const MAX_UPSTREAM_BYTES = 4 * 1024 * 1024;

export type ToolAnswer =
  | { ok: true; data: Record<string, unknown>; nIn?: number; nOut: number }
  | {
      ok: false;
      code: ToolErrorCode;
      field?: string;
      problem?: InputProblem;
      retryAfter?: number;
      /** Extra plain text after the fixed message (a task's reason for ending). */
      note?: string;
    };

export interface ToolDef<A> {
  name: ToolName;
  enabled: true;
  title: string;
  description: string;
  inputSchema: JsonSchema;
  outputSchema: JsonSchema;
  /** The scope the tool needs. Default `mti:read`. */
  scope?: 'mti:read' | 'mti:watch';
  /** Annotation hints merged over `HINTS`. */
  hints?: Partial<Record<keyof typeof HINTS, boolean>>;
  run(args: A, deps: CallDeps, signal: AbortSignal): Promise<ToolAnswer>;
}

const validator = new CfWorkerJsonSchemaValidator({ draft: '2020-12' });

const PROBLEMS: Record<InputProblem, string> = {
  bad_characters: 'contains characters that are not allowed',
  not_an_id: 'is not a valid ID',
  looks_like_email: 'looks like an email address',
};

function failText(a: Extract<ToolAnswer, { ok: false }>): string {
  switch (a.code) {
    case 'invalid_argument':
      return `The argument ${a.field ?? 'input'} ${a.problem ? PROBLEMS[a.problem] : 'was not accepted'}.`;
    case 'not_available_yet':
      return 'This lookup is not available yet.';
    case 'rate_limited':
      return `Too many requests. Try again in ${a.retryAfter ?? 60} seconds.`;
    case 'blocked':
      return 'This account or app cannot use MTI right now.';
    case 'tool_off':
      return 'This tool is turned off for now. Try again later.';
    case 'upstream_unavailable':
      return 'MTI could not answer right now. Try again shortly.';
    case 'timeout':
      return 'The lookup took too long and was stopped.';
    case 'too_many_tasks':
      return 'You have 3 tasks running. Wait for one to finish.';
    case 'too_many_packages':
      return 'Send at most 1,000 packages per call, or use a client that supports MCP tasks.';
    case 'internal':
      return 'Something went wrong on the MTI side.';
  }
}

/** Drops items from the end of `data[key]` until the JSON fits; sets `truncated` when it had to. */
export function fitToBudget(
  data: Record<string, unknown>,
  key?: string,
  reserve = 0,
): { data: Record<string, unknown>; kept: number } {
  const list = key ? data[key] : undefined;
  const size = (d: unknown) => JSON.stringify(d).length + reserve;
  if (!Array.isArray(list)) return { data, kept: 0 };
  if (size(data) <= MAX_STRUCTURED_CHARS) return { data, kept: list.length };
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (size({ ...data, [key as string]: list.slice(0, mid), truncated: true }) <= MAX_STRUCTURED_CHARS)
      lo = mid;
    else hi = mid - 1;
  }
  return { data: { ...data, [key as string]: list.slice(0, lo), truncated: true }, kept: lo };
}

export async function apiJson<T>(
  deps: CallDeps,
  req: { method: 'GET' | 'POST'; path: string; body?: unknown },
  signal: AbortSignal,
): Promise<{ ok: true; body: T } | { ok: false; status?: number; code: ToolErrorCode; retryAfter?: number }> {
  let res: Response;
  try {
    res = await callApi(deps.env, {
      method: req.method,
      path: req.path,
      body: req.body === undefined ? null : JSON.stringify(req.body),
      identity: deps.identity,
      requestId: deps.requestId,
      signal,
    });
  } catch {
    return { ok: false, code: signal.aborted ? 'timeout' : 'upstream_unavailable' };
  }
  const status = res.status;
  if (status !== 200) {
    let errBody: { error?: unknown } | null = null;
    if (status === 403) errBody = (await res.json().catch(() => null)) as { error?: unknown } | null;
    else await res.body?.cancel().catch(() => {});
    if (status === 400) return { ok: false, status, code: 'invalid_argument' };
    if (status === 404) return { ok: false, status, code: 'upstream_unavailable' };
    if (status === 401) {
      logEvent('error', 'mcp_api_assertion_rejected', { requestId: deps.requestId });
      return { ok: false, status, code: 'internal' };
    }
    if (status === 403) {
      const blocked = errBody?.error === 'blocked';
      return { ok: false, status, code: blocked ? 'blocked' : 'internal' };
    }
    if (status === 429) {
      const n = Number(res.headers.get('retry-after'));
      return {
        ok: false,
        status,
        code: 'rate_limited',
        retryAfter: Number.isInteger(n) && n > 0 && n <= 3600 ? n : 60,
      };
    }
    if (status === 501) return { ok: false, status, code: 'not_available_yet' };
    return { ok: false, status, code: 'upstream_unavailable' };
  }
  try {
    const reader = res.body?.getReader();
    if (!reader) return { ok: false, status, code: 'upstream_unavailable' };
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_UPSTREAM_BYTES) {
        await reader.cancel().catch(() => {});
        return { ok: false, status, code: 'upstream_unavailable' };
      }
      chunks.push(value);
    }
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.length;
    }
    return { ok: true, body: JSON.parse(new TextDecoder().decode(buf)) as T };
  } catch {
    return { ok: false, status, code: signal.aborted ? 'timeout' : 'upstream_unavailable' };
  }
}

/** The tool-error result for an answer, with the request ID. Also used for the result of a finished task. */
export function failureResult(requestId: string, a: Extract<ToolAnswer, { ok: false }>) {
  return {
    isError: true as const,
    content: [
      {
        type: 'text' as const,
        text: `${failText(a)}${a.note ? ` ${a.note}` : ''} Request ID: ${requestId}.`,
      },
    ],
  };
}

function failure(deps: CallDeps, a: Extract<ToolAnswer, { ok: false }>) {
  deps.stats.toolError = a.code;
  return failureResult(deps.requestId, a);
}

export function registerTool(server: McpServer, def: ToolDef<never>, deps: CallDeps): void {
  server.registerTool(
    def.name,
    {
      title: def.title,
      description: def.description,
      inputSchema: fromJsonSchema(def.inputSchema as never, validator),
      outputSchema: fromJsonSchema(def.outputSchema as never, validator),
      annotations: { title: def.title, ...HINTS, ...def.hints },
      scopeChallenge: requireScopes(def.scope ?? 'mti:read'),
    },
    (async (args: unknown, ctx: { mcpReq: { signal: AbortSignal } }) => {
      deps.stats.tool = def.name;
      try {
        let off: string | null | undefined;
        try {
          off = await deps.env.SETTINGS.get(`mcp:tool:${def.name}:off`, { cacheTtl: 60 });
        } catch {
          logEvent('warn', 'mcp_tool_switch_error', { tool: def.name });
        }
        if (off !== null && off !== undefined) return failure(deps, { ok: false, code: 'tool_off' });

        const bad = findBadText(args);
        if (bad)
          return failure(deps, {
            ok: false,
            code: 'invalid_argument',
            field: bad,
            problem: 'bad_characters',
          });

        const signal = AbortSignal.any([deps.signal, ctx.mcpReq.signal]);
        const answer = await def.run(args as never, deps, signal);
        if (!answer.ok) return failure(deps, answer);
        deps.stats.nIn = answer.nIn;
        deps.stats.nOut = answer.nOut;
        const structuredContent = answer.data;
        return {
          structuredContent,
          content: [{ type: 'text' as const, text: JSON.stringify(structuredContent) }],
          ...(def.name === 'mti_list_sources' ? {} : { _meta: { ...TRUST_META } }),
        };
      } catch {
        return failure(deps, { ok: false, code: 'internal' });
      }
    }) as never,
  );
}

/** The "as of" time: the API's when it gives one, else now. */
export function asOfFrom(upstream: unknown, deps: CallDeps): string {
  return typeof upstream === 'string' && /^\d{4}-\d{2}-\d{2}/.test(upstream) && upstream.length <= 40
    ? upstream
    : deps.now().toISOString();
}
