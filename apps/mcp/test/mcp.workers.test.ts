import { createExecutionContext, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { MCP_HEADERS, type McpIdentity, verifyMcpAssertion } from '@ti/core/mcp-user';
import { API_SECURITY_HEADERS } from '@ti/core/security-headers';
import { describe, expect, it } from 'vitest';
import { callApi } from '../src/api';
import type { Env } from '../src/env';
import { NotImplementedError } from '../src/errors';
import worker from '../src/index';
import type { McpTask } from '../src/tasks/mcp-task';
import { TOOL_ORDER } from '../src/tools';
import { BASE_ENV } from './support/mcp';

const E = env as unknown as Env;

async function call(method: string, path: string, headers: Record<string, string> = {}) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(
    new Request(`https://mti.test${path}`, { method, headers }) as never,
    BASE_ENV,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return res;
}

function expectCommonHeaders(res: Response) {
  for (const [name, value] of Object.entries(API_SECURITY_HEADERS))
    expect(res.headers.get(name), name).toBe(value);
  expect(res.headers.get('Cache-Control')).toBe('no-store');
  expect(res.headers.get('x-request-id')).toMatch(/^[0-9a-f-]{36}$/);
  expect(res.headers.get('set-cookie')).toBeNull();
}

describe('ti-mcp fetch handler', () => {
  it('POST /mcp with no token answers 401 (the not_ready stub is gone)', async () => {
    const res = await call('POST', '/mcp');
    expect(res.status).toBe(401);
    expectCommonHeaders(res);
  });
  it.each(['GET', 'DELETE', 'PUT', 'PATCH'])('%s /mcp answers 405 with Allow: POST', async (method) => {
    const res = await call(method, '/mcp');
    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('POST');
    expectCommonHeaders(res);
  });
  it.each(['/', '/mcp/', '/mcpx', '/v1/me', '/.well-known/oauth-protected-resource'])(
    '%s answers 404',
    async (path) => {
      const res = await call('GET', path);
      expect(res.status).toBe(404);
      expectCommonHeaders(res);
    },
  );
  it.each(['/.well-known/oauth-protected-resource/mcp', '/mcp/server-card'])('%s is served', async (path) => {
    const res = await call('GET', path);
    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toBeNull();
  });
  it('keeps a well-formed incoming request id and replaces a malformed one', async () => {
    const kept = await call('GET', '/mcp', { 'x-request-id': 'caller-chosen-id-1' });
    expect(kept.headers.get('x-request-id')).toBe('caller-chosen-id-1');
    const replaced = await call('GET', '/mcp', { 'x-request-id': 'bad id with spaces' });
    expect(replaced.headers.get('x-request-id')).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('callApi', () => {
  const identity: McpIdentity = { sub: 'user_2abcdefghijk', scopes: ['mti:read'], clientId: 'client-1' };
  type Echo = { method: string; url: string; headers: Record<string, string>; body: string };

  it('sends an assertion that verifies on the API side, and a body whose hash matches', async () => {
    const body = JSON.stringify({ packages: [{ purl: 'pkg:npm/lodash@4.17.20' }] });
    const res = await callApi(E, {
      method: 'post',
      path: '/v1/packages/check?x=1',
      body,
      identity,
      requestId: 'req-0001',
    });
    const echo = (await res.json()) as Echo;
    expect(echo.method).toBe('POST');
    expect(new URL(echo.url).pathname + new URL(echo.url).search).toBe('/v1/packages/check?x=1');
    expect(echo.body).toBe(body);
    const verified = await verifyMcpAssertion([E.MCP_HMAC_SECRET], new Headers(echo.headers), {
      requestId: echo.headers['x-request-id'] as string,
      method: echo.method,
      pathWithQuery: '/v1/packages/check?x=1',
      body: new TextEncoder().encode(echo.body).buffer as ArrayBuffer,
    });
    expect(verified).toEqual(identity);
    expect(echo.headers['x-request-id']).toBe('req-0001');
    // A different body fails: the hash is bound.
    const tampered = await verifyMcpAssertion([E.MCP_HMAC_SECRET], new Headers(echo.headers), {
      requestId: 'req-0001',
      method: 'POST',
      pathWithQuery: '/v1/packages/check?x=1',
      body: new TextEncoder().encode('{}').buffer as ArrayBuffer,
    });
    expect(tampered).toBeNull();
  });

  it('signs a GET with no body', async () => {
    const res = await callApi(E, { method: 'GET', path: '/v1/me/watch', identity, requestId: 'req-0002' });
    const echo = (await res.json()) as Echo;
    expect(echo.body).toBe('');
    expect(echo.headers['content-type']).toBeUndefined();
    const verified = await verifyMcpAssertion([E.MCP_HMAC_SECRET], new Headers(echo.headers), {
      requestId: 'req-0002',
      method: 'GET',
      pathWithQuery: '/v1/me/watch',
      body: null,
    });
    expect(verified).toEqual(identity);
  });

  it('sends only its own headers: nothing from the client leaks, and no token', async () => {
    const res = await callApi(E, { method: 'GET', path: '/v1/search?q=a', identity, requestId: 'req-0003' });
    const echo = (await res.json()) as Echo;
    expect(Object.keys(echo.headers).sort()).toEqual(
      ['accept', 'host', 'x-request-id', ...Object.values(MCP_HEADERS)].sort(),
    );
    for (const name of ['authorization', 'cookie', 'cf-connecting-ip', 'x-forwarded-for', 'user-agent'])
      expect(echo.headers[name], name).toBeUndefined();
  });

  it('uses the internal origin, and refuses a path that would leave it', async () => {
    const ok = (await (
      await callApi(E, { method: 'GET', path: '/v1/sources', identity, requestId: 'r1' })
    ).json()) as Echo;
    expect(new URL(ok.url).origin).toBe('https://ti-api.internal');
    for (const path of ['//evil.example/x', 'https://evil.example/x', 'v1/me', '/\\evil.example'])
      await expect(callApi(E, { method: 'GET', path, identity, requestId: 'r1' }), path).rejects.toThrow();
  });

  it('refuses to call without a signing secret', async () => {
    await expect(
      callApi(
        { ...E, MCP_HMAC_SECRET: undefined },
        { method: 'GET', path: '/v1/me', identity, requestId: 'r1' },
      ),
    ).rejects.toThrow(/not configured/);
  });
});

describe('skeleton', () => {
  it('lists the 13 tools in the fixed order', () => {
    expect([...TOOL_ORDER]).toEqual([
      'mti_check_packages',
      'mti_check_sbom',
      'mti_get_entry',
      'mti_search',
      'mti_latest_threats',
      'mti_search_breaches',
      'mti_search_incidents',
      'mti_get_technique',
      'mti_list_sources',
      'mti_watch_add',
      'mti_watch_remove',
      'mti_watch_list',
      'mti_deep_query',
    ]);
  });
  it('keeps a stub for each tool that is not built here, and enables the twelve that are', async () => {
    const built = [
      'mti_check_packages',
      'mti_get_entry',
      'mti_search',
      'mti_latest_threats',
      'mti_search_breaches',
      'mti_search_incidents',
      'mti_get_technique',
      'mti_list_sources',
      'mti_deep_query',
      'mti_watch_add',
      'mti_watch_remove',
      'mti_watch_list',
    ];
    for (const name of TOOL_ORDER) {
      const mod = (await import(`../src/tools/${name}.ts`)) as { tool: { name: string; enabled: boolean } };
      expect(mod.tool.name).toBe(name);
      expect(mod.tool.enabled).toBe(built.includes(name));
      if (!built.includes(name)) expect(mod.tool).toEqual({ name, enabled: false });
    }
  });
  it('has no-op extension points', async () => {
    for (const ext of ['skills', 'tasks', 'listen', 'apps', 'uploads']) {
      const mod = (await import(`../src/ext/${ext}.ts`)) as { register: () => void };
      expect(mod.register()).toBeUndefined();
    }
  });
  it('binds the McpTask Durable Object', async () => {
    const stub = E.MCP_TASKS.get(E.MCP_TASKS.idFromName('t'));
    expect(await (stub as unknown as McpTask).exists('user_x', '0'.repeat(26))).toBe(false);
  });
});
