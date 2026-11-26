import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env as rawEnv } from 'cloudflare:workers';
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from '@modelcontextprotocol/server';
import type { Env } from '../../src/env';
import worker from '../../src/index';
import { ISS, RES } from './tokens';

export const MODERN = '2026-07-28';
export const BASE_ENV = {
  ...(rawEnv as unknown as Env),
  MCP_RESOURCE_URL: RES,
  CLERK_ISSUER: ISS,
  MCP_ALLOWED_ORIGINS: 'https://app.allowed.test',
} as Env;

export function modernBody(method: string, params: Record<string, unknown> = {}, id: number | string = 1) {
  return {
    jsonrpc: '2.0',
    id,
    method,
    params: {
      ...params,
      _meta: {
        [PROTOCOL_VERSION_META_KEY]: MODERN,
        [CLIENT_INFO_META_KEY]: { name: 'test-client', version: '0.0.0' },
        [CLIENT_CAPABILITIES_META_KEY]: {},
        ...((params._meta as object) ?? {}),
      },
    },
  };
}

export function modernHeaders(method: string, name?: string, token?: string): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': MODERN,
    'mcp-method': method,
    ...(name ? { 'mcp-name': name } : {}),
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

export function modernCall(
  token: string | undefined,
  method: string,
  params: Record<string, unknown> = {},
  extra: Record<string, string> = {},
) {
  const name = typeof params.name === 'string' ? params.name : undefined;
  return {
    headers: { ...modernHeaders(method, name, token), ...extra },
    body: JSON.stringify(modernBody(method, params)),
  };
}

export function legacyHeaders(token?: string, version = '2025-11-25'): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': version,
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}
export const legacyInit = (id = 1) => ({
  jsonrpc: '2.0',
  id,
  method: 'initialize',
  params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'legacy', version: '1' } },
});

export async function send(
  init: { method?: string; headers?: Record<string, string>; body?: BodyInit | null; signal?: AbortSignal },
  env: Env = BASE_ENV,
  path = '/mcp',
): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(
    new Request(`https://mti.test${path}`, { method: 'POST', ...init }) as never,
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}

/** The JSON of a JSON answer, or the JSON in the first `data:` line of an SSE answer. */
export async function bodyOf(res: Response): Promise<any> {
  const text = await res.text();
  if ((res.headers.get('content-type') ?? '').includes('text/event-stream')) {
    const line = text.split('\n').find((l) => l.startsWith('data:'));
    return line ? JSON.parse(line.slice(5)) : null;
  }
  return text ? JSON.parse(text) : null;
}
