import { describe, expect, it } from 'vitest';
import {
  MCP_HEADERS,
  MCP_SKEW_SECONDS,
  type McpIdentity,
  signMcpAssertion,
  verifyMcpAssertion,
} from './mcp-user';

const SECRET = 'current-secret';
const NEXT = 'next-secret';
const ID: McpIdentity = { sub: 'user_2abcdefghijk', scopes: ['mti:watch', 'mti:read'], clientId: 'client-1' };
const body = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer;
const NOW = new Date('2026-11-26T10:00:00Z');
const TS = Math.floor(NOW.getTime() / 1000);
const REQ: { requestId: string; method: string; pathWithQuery: string; body: ArrayBuffer | null } = {
  requestId: 'req-1',
  method: 'POST',
  pathWithQuery: '/v1/packages/check?a=1',
  body: body('{"x":1}'),
};

const headersFor = async (over: Partial<typeof REQ> = {}, secret = SECRET, id = ID, ts = TS) =>
  new Headers(await signMcpAssertion(secret, id, { ...REQ, ...over }, ts));
const verify = (h: Headers, over: Partial<typeof REQ> = {}, secrets = [SECRET, undefined], now = NOW) =>
  verifyMcpAssertion(secrets, h, { ...REQ, ...over }, now);

describe('MCP assertion', () => {
  it('verifies a good assertion and returns the identity with sorted scopes', async () => {
    expect(await verify(await headersFor())).toEqual({
      sub: ID.sub,
      scopes: ['mti:read', 'mti:watch'],
      clientId: 'client-1',
    });
  });
  it('signs a null body as an empty one', async () => {
    const h = await headersFor({ body: null });
    expect(await verify(h, { body: null })).not.toBeNull();
    expect(await verify(h, { body: new ArrayBuffer(0) })).not.toBeNull();
  });
  it('rejects a wrong secret and an unset secret list', async () => {
    const h = await headersFor();
    expect(await verify(h, {}, ['other'])).toBeNull();
    expect(await verify(h, {}, [undefined, ''])).toBeNull();
    expect(await verify(h, {}, [])).toBeNull();
  });
  it('accepts the next secret during rotation, in either slot', async () => {
    const h = await headersFor({}, NEXT);
    expect(await verify(h, {}, [SECRET, NEXT])).not.toBeNull();
    expect(await verify(await headersFor(), {}, [NEXT, SECRET])).not.toBeNull();
    expect(await verify(h, {}, [SECRET, undefined])).toBeNull();
  });
  it('rejects an old or a future timestamp, and allows the edge of the skew', async () => {
    const at = (offset: number) => headersFor({}, SECRET, ID, TS + offset);
    expect(await verify(await at(-MCP_SKEW_SECONDS - 1))).toBeNull();
    expect(await verify(await at(MCP_SKEW_SECONDS + 1))).toBeNull();
    expect(await verify(await at(-MCP_SKEW_SECONDS))).not.toBeNull();
    expect(await verify(await at(MCP_SKEW_SECONDS))).not.toBeNull();
  });
  it.each([
    ['body', { body: body('{"x":2}') }],
    ['path', { pathWithQuery: '/v1/packages/other?a=1' }],
    ['query', { pathWithQuery: '/v1/packages/check?a=2' }],
    ['method', { method: 'PUT' }],
    ['request id', { requestId: 'req-2' }],
  ])('rejects a changed %s', async (_name, over) => {
    expect(await verify(await headersFor(), over)).toBeNull();
  });
  it('takes the method case-insensitively', async () => {
    expect(await verify(await headersFor(), { method: 'post' })).not.toBeNull();
  });
  it('accepts scopes in any order', async () => {
    const h = await headersFor();
    h.set(MCP_HEADERS.scopes, 'mti:watch mti:read');
    expect(await verify(h)).not.toBeNull();
    h.set(MCP_HEADERS.scopes, 'mti:read mti:watch');
    expect(await verify(h)).not.toBeNull();
  });
  it('rejects scopes changed after signing, and unknown scopes even when signed', async () => {
    const h = await headersFor();
    h.set(MCP_HEADERS.scopes, 'mti:read');
    expect(await verify(h)).toBeNull();
    const signed = await headersFor({}, SECRET, { ...ID, scopes: ['mti:read', 'mti:admin'] });
    expect(await verify(signed)).toBeNull();
  });
  it('rejects a malformed sub even when signed', async () => {
    for (const sub of [
      'admin',
      'user_short',
      'user_has space1234',
      `user_${'a'.repeat(65)}`,
      'USER_2abcdefghijk',
    ]) {
      const h = await headersFor({}, SECRET, { ...ID, sub });
      expect(await verify(h), sub).toBeNull();
    }
  });
  it('rejects a bad client id even when signed', async () => {
    for (const clientId of ['', 'a'.repeat(513), 'bad\nid', 'café']) {
      // Signed with the bad value (headers can't carry some of these), then read back from a plain map.
      const signed = await signMcpAssertion(SECRET, { ...ID, clientId }, REQ, TS);
      const h = new Headers({ ...signed, [MCP_HEADERS.client]: 'x' });
      const real = { get: (n: string) => (n === MCP_HEADERS.client ? clientId : h.get(n)) } as Headers;
      expect(await verify(real), JSON.stringify(clientId)).toBeNull();
    }
  });
  it('fails closed on every missing header', async () => {
    for (const name of Object.values(MCP_HEADERS)) {
      const h = await headersFor();
      h.delete(name);
      expect(await verify(h), name).toBeNull();
    }
  });
  it('rejects a non-numeric timestamp', async () => {
    const h = await headersFor();
    h.set(MCP_HEADERS.ts, `${TS}abc`);
    expect(await verify(h)).toBeNull();
  });
  it('refuses to sign with an empty secret', async () => {
    await expect(signMcpAssertion('', ID, REQ, TS)).rejects.toThrow();
  });
});
