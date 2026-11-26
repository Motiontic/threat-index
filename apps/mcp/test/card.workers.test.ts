import { SUPPORTED_PROTOCOL_VERSIONS } from '@modelcontextprotocol/server';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { SERVER_CARD_SCHEMA, serverCard } from '../src/card';
import { SERVER_INFO } from '../src/config';
import { BASE_ENV, bodyOf, modernCall, send } from './support/mcp';
import { goodPayload, type JwksSpy, makeKey, mockJwks, RES, signJwt, type TestKey } from './support/tokens';

const get = (init: RequestInit = {}, env = BASE_ENV) =>
  send({ method: 'GET', ...init } as never, env, '/mcp/server-card');
let jwks: JwksSpy | undefined;
afterEach(() => {
  jwks?.restore();
  jwks = undefined;
  resetJwksCacheForTests();
});

describe('server card', () => {
  it('is the exact JSON, with the right media type, CORS and ETag', async () => {
    const res = await get();
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/mcp-server-card+json');
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-expose-headers')).toBe('ETag');
    expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
    expect(res.headers.get('etag')).toMatch(/^"[0-9a-f]{32}"$/);
    expect(await res.json()).toEqual({
      $schema: SERVER_CARD_SCHEMA,
      name: 'com.motiontic/mti',
      version: '1.0.0',
      title: 'MTI (Motiontic Threat Index)',
      description:
        'Known vulnerabilities, malicious packages, exploitation signals, breaches and AI incidents.',
      websiteUrl: 'https://mti.test',
      repository: {
        url: 'https://github.com/Motiontic/threat-index',
        source: 'github',
        subfolder: 'apps/mcp',
      },
      remotes: [
        {
          type: 'streamable-http',
          url: RES,
          supportedProtocolVersions: ['2026-07-28', ...SUPPORTED_PROTOCOL_VERSIONS],
        },
      ],
    });
    expect(serverCard(BASE_ENV).description.length).toBeLessThanOrEqual(100);
  });
  it('no tool list, capabilities or internals', () => {
    const text = JSON.stringify(serverCard(BASE_ENV));
    for (const w of ['tools', 'capabilities', 'ti-api', 'internal', 'binding', 'KV'])
      expect(text).not.toContain(w);
  });
  it('conditional GET: a matching If-None-Match (list, W/, *) → 304 with no body', async () => {
    const etag = (await get()).headers.get('etag') as string;
    for (const inm of [etag, `"other", ${etag}`, `W/${etag}`, '*']) {
      const res = await get({ headers: { 'if-none-match': inm } });
      expect(res.status, inm).toBe(304);
      expect(await res.text()).toBe('');
      expect(res.headers.get('etag')).toBe(etag);
    }
    expect((await get({ headers: { 'if-none-match': '"nope"' } })).status).toBe(200);
  });
  it('HEAD, OPTIONS and other methods', async () => {
    const head = await get({ method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe('');
    const opt = await get({ method: 'OPTIONS' });
    expect(opt.status).toBe(204);
    expect(opt.headers.get('access-control-allow-methods')).toBe('GET, HEAD');
    expect(opt.headers.get('access-control-allow-headers')).toBe('Content-Type, If-None-Match');
    expect((await get({ method: 'POST', body: '{}' })).status).toBe(405);
    expect((await get({ method: 'DELETE' })).status).toBe(405);
  });
  it('429 when limited, keeping the CORS header', async () => {
    const env = { ...BASE_ENV, RL_MCP_ANON: { limit: async () => ({ success: false }) } } as typeof BASE_ENV;
    const res = await get({}, env);
    expect(res.status).toBe(429);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });
  it('matches server/discover: version, title and supported versions', async () => {
    const key: TestKey = await makeKey('k1');
    jwks = mockJwks([key]);
    const token = await signJwt(key, goodPayload({}, Math.floor(Date.now() / 1000)));
    const c = modernCall(token, 'server/discover');
    const b = await bodyOf(await send({ headers: c.headers, body: c.body }));
    const r = b.result;
    const card = serverCard(BASE_ENV);
    const meta = r._meta['io.modelcontextprotocol/serverInfo'];
    expect(meta).toEqual({ name: SERVER_INFO.name, title: card.title, version: card.version });
    // SDK 2.4.0: discover lists only the modern revision; the card also lists the 2025 revisions the endpoint serves
    // statelessly. Every version discover names is on the card, and the card's list is the SDK's list plus it.
    const versions = card.remotes[0]?.supportedProtocolVersions ?? [];
    for (const v of r.supportedVersions) expect(versions).toContain(v);
    expect(versions).toEqual(['2026-07-28', ...SUPPORTED_PROTOCOL_VERSIONS]);
  });
});
