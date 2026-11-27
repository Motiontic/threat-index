import type { McpIdentity } from '@ti/core/mcp-user';
import { sealCursor } from '../cursor';
import type { Env } from '../env';
import type { ToolName } from '../tools';
import type { CreateResult, GetResult, McpTask, PageOut, TaskKind } from './mcp-task';

/** The one object that holds this user's tasks. Another user's ID reaches another object and is not found. */
export function taskStub(env: Env, sub: string): TaskApi {
  return env.MCP_TASKS.get(env.MCP_TASKS.idFromName(`user:${sub}`)) as unknown as TaskApi;
}

/** The object's RPC methods with plain types (the generated RPC types turn `unknown` fields into `never`). */
export interface TaskApi {
  exists: McpTask['exists'];
  createCheck(identity: McpIdentity, tokenExp: number, packages: unknown[]): Promise<CreateResult>;
  startDeepQuery(
    identity: McpIdentity,
    tokenExp: number,
    query: { template: string; params: Record<string, string> },
  ): Promise<CreateResult>;
  get(sub: string, taskId: string): Promise<GetResult>;
  page(sub: string, taskId: string, kind: TaskKind, offset: number): Promise<PageOut | null>;
  cancel(sub: string, taskId: string): Promise<{ found: boolean }>;
}

export const taskExists = (env: Env, sub: string, taskId: string): Promise<boolean> =>
  taskStub(env, sub).exists(sub, taskId);

const TOOL_OF: Record<TaskKind, ToolName> = { check: 'mti_check_packages', deep_query: 'mti_deep_query' };

/** A cursor for the next page of a task's stored result: tool, user and arguments `{}` bound, state `{ t, o }`. */
export async function sealTaskCursor(
  env: Env,
  kind: TaskKind,
  sub: string,
  taskId: string,
  offset: number,
): Promise<string | null> {
  const secret = env.MCP_HMAC_SECRET;
  return secret ? sealCursor(secret, TOOL_OF[kind], {}, { t: taskId, o: offset }, sub) : null;
}

/** A page of a stored result with its `nextCursor` sealed, or null when the task is gone. */
export async function readTaskPage(
  env: Env,
  kind: TaskKind,
  sub: string,
  taskId: string,
  offset: number,
): Promise<Record<string, unknown> | null> {
  const page: PageOut | null = await taskStub(env, sub).page(sub, taskId, kind, offset);
  return page ? withCursor(env, kind, sub, taskId, page) : null;
}

export async function withCursor(
  env: Env,
  kind: TaskKind,
  sub: string,
  taskId: string,
  page: PageOut,
): Promise<Record<string, unknown>> {
  const nextCursor = page.next === null ? null : await sealTaskCursor(env, kind, sub, taskId, page.next);
  return { ...page.data, nextCursor };
}
