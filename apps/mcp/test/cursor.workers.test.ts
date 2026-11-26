import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { MAX_CURSOR_CHARS, openCursor, sealCursor } from '../src/cursor';
import { fakeApi, ok, withApi } from './support/fake-api';
import { BASE_ENV, bodyOf, modernCall, send } from './support/mcp';
import { goodPayload, type JwksSpy, makeKey, mockJwks, signJwt, type TestKey } from './support/tokens';

const S = 'secret-one';
const N = 'secret-next';
const args = { query: 'a', limit: 5 };
const NOW = 1_800_000_000;

describe('cursor seal and open', () => {
  it('round-trips each state shape', async () => {
    for (const st of [{ c: 'abc_DEF-1' }, { p: 3, k: 24 }, { o: 1000 }] as const) {
      const c = await sealCursor(S, 'mti_search', args, st, NOW);
      expect(await openCursor([S], 'mti_search', args, c, NOW + 10)).toEqual(st);
    }
  });
  it('a cursor sealed with the NEXT secret opens', async () => {
    const c = await sealCursor(N, 'mti_search', args, { o: 5 }, NOW);
    expect(await openCursor([S, N], 'mti_search', args, c, NOW)).toEqual({ o: 5 });
    expect(await openCursor([S], 'mti_search', args, c, NOW)).toBeNull();
  });
  it('fails for every kind of bad cursor', async () => {
    const good = await sealCursor(S, 'mti_search', args, { o: 5 }, NOW);
    const [p, m] = good.split('.') as [string, string];
    const flip = (s: string) => `${s.slice(0, -2)}${s.endsWith('A') ? 'B' : 'A'}${s.slice(-1)}`;
    const bad: [string, string | null][] = [
      ['changed payload byte', `${flip(p)}.${m}`],
      ['changed mac byte', `${p}.${flip(m)}`],
      ['bad shape', 'nodots'],
      ['bad shape 2', 'a.b.c'],
      ['over 512 characters', `${'a'.repeat(600)}.${m}`],
      ['not base64url', '!!!.???'],
      ['expired', await sealCursor(S, 'mti_search', args, { o: 5 }, NOW - 7200)],
      ['out of range offset', await sealCursor(S, 'mti_search', args, { o: 1001 }, NOW)],
      ['out of range page', await sealCursor(S, 'mti_search', args, { p: 41, k: 0 }, NOW)],
      ['out of range skip', await sealCursor(S, 'mti_search', args, { p: 1, k: 25 }, NOW)],
      ['bad api cursor', await sealCursor(S, 'mti_search', args, { c: 'has space' }, NOW)],
      ['empty api cursor', await sealCursor(S, 'mti_search', args, { c: '' }, NOW)],
    ];
    for (const [name, c] of bad)
      expect(await openCursor([S], 'mti_search', args, c as string, NOW), name).toBeNull();
    expect(await openCursor([S], 'mti_get_entry', args, good, NOW), 'other tool').toBeNull();
    expect(
      await openCursor([S], 'mti_search', { ...args, query: 'b' }, good, NOW),
      'other arguments',
    ).toBeNull();
    expect(MAX_CURSOR_CHARS).toBe(512);
  });
  it('the arguments hash ignores the cursor itself and key order', async () => {
    const c = await sealCursor(S, 'mti_search', { limit: 5, query: 'a' }, { o: 1 }, NOW);
    expect(await openCursor([S], 'mti_search', { query: 'a', cursor: c, limit: 5 }, c, NOW)).toEqual({
      o: 1,
    });
  });
});

describe('cursor at the edge', () => {
  let key: TestKey;
  let token: string;
  let jwks: JwksSpy;
  beforeAll(async () => {
    key = await makeKey('k1');
    token = await signJwt(key, goodPayload({}, Math.floor(Date.now() / 1000)));
  });
  afterEach(() => {
    jwks?.restore();
    resetJwksCacheForTests();
  });
  it('a bad cursor → HTTP 200 -32602 with data.field, echoing the id, before any API call', async () => {
    jwks = mockJwks([key]);
    const api = fakeApi(() => ok({}));
    const c = modernCall(token, 'tools/call', {
      name: 'mti_search',
      arguments: { query: 'a', cursor: 'x.y' },
    });
    const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api));
    expect(res.status).toBe(200);
    const b = await bodyOf(res);
    expect(b.id).toBe(1);
    expect(b.error.code).toBe(-32602);
    expect(b.error.data.field).toBe('cursor');
    expect(b.error.data.requestId).toBeTruthy();
    expect(api.calls).toHaveLength(0);
  });
  it('a cursor for another tool, changed arguments, and one over 512 characters all give -32602', async () => {
    jwks = mockJwks([key]);
    const api = fakeApi(() => ok({}));
    const env = withApi(BASE_ENV, api);
    const other = await sealCursor(
      BASE_ENV.MCP_HMAC_SECRET as string,
      'mti_get_entry',
      { query: 'a' },
      { o: 1 },
    );
    const changed = await sealCursor(
      BASE_ENV.MCP_HMAC_SECRET as string,
      'mti_search',
      { query: 'zzz' },
      { o: 1 },
    );
    for (const cursor of [other, changed, 'a'.repeat(600)]) {
      const c = modernCall(token, 'tools/call', { name: 'mti_search', arguments: { query: 'a', cursor } });
      const b = await bodyOf(await send({ headers: c.headers, body: c.body }, env));
      expect(b.error?.code ?? b.result?.isError).toBeTruthy();
    }
    expect(api.calls).toHaveLength(0);
  });
});
