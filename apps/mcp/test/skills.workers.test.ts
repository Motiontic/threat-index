import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { INSTRUCTIONS, instructionsFor } from '../src/instructions';
import { SKILL_DIGESTS, SKILL_FILES } from '../src/skills.generated';
import { TOOL_ORDER } from '../src/tools';
import { fakeApi, withApi } from './support/fake-api';
import { BASE_ENV, bodyOf, modernCall, send } from './support/mcp';
import { goodPayload, type JwksSpy, makeKey, mockJwks, signJwt, type TestKey } from './support/tokens';

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

async function rpc(method: string, params: Record<string, unknown> = {}, tok: string | null = token) {
  // The modern transport wants the target URI in Mcp-Name on resource calls.
  const extra: Record<string, string> = typeof params.uri === 'string' ? { 'mcp-name': params.uri } : {};
  jwks = mockJwks([key]);
  const api = fakeApi(() => new Response('{}'));
  const c = modernCall(tok ?? undefined, method, params, extra);
  const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api));
  return { res, api, body: res.status === 200 ? await bodyOf(res) : null };
}

const AWA = 'skill://mti/are-we-affected/SKILL.md';
const SI = 'skill://mti/safe-install/SKILL.md';

describe('skills over MCP', () => {
  it('skills/list returns both skills at skill://mti/ with a public one-hour cache hint', async () => {
    const { body } = await rpc('skills/list');
    const skills = body.result.skills as any[];
    expect(skills.map((s) => s.uri).sort()).toEqual([AWA, SI]);
    for (const s of skills) {
      expect(Object.keys(s.frontmatter).sort()).toEqual(['description', 'name']);
      const lines = SKILL_FILES[`${s.frontmatter.name}/SKILL.md`]?.split('\n') ?? [];
      const fm = lines.slice(1, lines.indexOf('---', 1));
      const parsed = Object.fromEntries(
        fm.map((l) => [l.slice(0, l.indexOf(': ')), l.slice(l.indexOf(': ') + 2)]),
      );
      expect(s.frontmatter).toEqual(parsed);
      expect(s.frontmatter).toEqual({ name: s.frontmatter.name, description: s.frontmatter.description });
    }
    expect(body.result.cacheScope).toBe('public');
    expect(body.result.ttlMs).toBe(3_600_000);
  });

  it('served digests and sizes equal the bundler sha256 and byte length for every file', async () => {
    const { body } = await rpc('skills/list');
    const listed = body.result.skills as any[];
    expect(listed).toHaveLength(2);
    let seen = 0;
    for (const s of listed) {
      const got = await rpc('skills/get', { uri: s.uri });
      for (const r of got.body.result.skill.resources as any[]) {
        const path = r.uri.slice('skill://mti/'.length);
        expect(r.digest, path).toBe(SKILL_DIGESTS[path]);
        expect(r.size, path).toBe(new TextEncoder().encode(SKILL_FILES[path]).length);
        seen++;
      }
    }
    expect(seen).toBe(Object.keys(SKILL_DIGESTS).length);
  });

  it('skills/get and resources/read return the exact bundled bytes', async () => {
    for (const [uri, path] of [
      [AWA, 'are-we-affected/SKILL.md'],
      [SI, 'safe-install/SKILL.md'],
      ['skill://mti/are-we-affected/references/lockfiles.md', 'are-we-affected/references/lockfiles.md'],
    ] as const) {
      const r = await rpc('resources/read', { uri });
      expect(r.body.result.contents[0].text, uri).toBe(SKILL_FILES[path]);
      expect(r.body.result.contents[0].uri).toBe(uri);
    }
  });

  it('resources/list returns exactly the two SKILL.md URIs', async () => {
    const { body } = await rpc('resources/list');
    expect((body.result.resources as any[]).map((r) => r.uri).sort()).toEqual([AWA, SI]);
  });

  it('resources/directory/read lists references/ for are-we-affected', async () => {
    const { body } = await rpc('resources/directory/read', { uri: 'skill://mti/are-we-affected' });
    const text = JSON.stringify(body.result);
    expect(text).toContain('references');
    expect(text).toContain('SKILL.md');
  });

  it.each([
    'https://example.com/x',
    'file:///etc/passwd',
    'skill://other/are-we-affected/SKILL.md',
    'skill://mti/../x',
    'skill://mti/are-we-affected/../../x',
    'skill://mti/nope/SKILL.md',
  ])('resources/read of %s is refused with -32602, no echo, and never reaches ti-api', async (uri) => {
    const { body, api } = await rpc('resources/read', { uri });
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toBe('Invalid params');
    expect(Object.keys(body.error.data ?? {})).toEqual(['requestId']);
    expect(JSON.stringify(body)).not.toContain(uri);
    expect(api.calls).toHaveLength(0);
  });

  it('server/discover lists the skills extension and resources.listChanged false', async () => {
    const { body } = await rpc('server/discover');
    expect(body.result.capabilities.extensions['io.modelcontextprotocol/skills']).toMatchObject({
      directoryRead: true,
    });
    expect(body.result.capabilities.resources).toMatchObject({ listChanged: false });
    expect(body.result.capabilities.tools).toBeDefined();
  });

  it.each([
    ['skills/list', {}],
    ['skills/get', { uri: AWA }],
    ['resources/read', { uri: AWA }],
    ['resources/list', {}],
    ['resources/templates/list', {}],
    ['resources/directory/read', { uri: 'skill://mti/are-we-affected' }],
  ])('%s without a token gets the 401 challenge', async (method, params) => {
    const { res, api } = await rpc(method, params, null);
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('Bearer');
    expect(api.calls).toHaveLength(0);
  });

  it.each([
    ['skills/list', {}],
    ['skills/get', { uri: AWA }],
    ['resources/read', { uri: AWA }],
    ['resources/templates/list', {}],
    ['resources/directory/read', { uri: 'skill://mti/are-we-affected' }],
  ])('%s with a token lacking mti:read gets 403', async (method, params) => {
    const t = await signJwt(key, goodPayload({ scope: 'mti:watch' }));
    const { res } = await rpc(method, params, t);
    expect(res.status).toBe(403);
    expect(res.headers.get('www-authenticate')).toContain('insufficient_scope');
  });
});

describe('instructions', () => {
  it('are under 4,096 characters with every tool enabled', () => {
    expect(instructionsFor(TOOL_ORDER).length).toBeLessThan(4096);
  });
  it('list only enabled tools, in order, and match a snapshot', () => {
    expect(instructionsFor(['mti_search', 'mti_check_packages'])).toContain('- mti_check_packages:');
    expect(instructionsFor(['mti_search', 'mti_check_packages'])).not.toContain('mti_deep_query');
    expect(instructionsFor([])).not.toContain('- mti_');
    expect(instructionsFor(TOOL_ORDER)).toMatchSnapshot();
    expect(INSTRUCTIONS).toBe(instructionsFor(TOOL_ORDER.filter((n) => INSTRUCTIONS.includes(`- ${n}:`))));
  });
  it('has no link of any kind and names the skills', () => {
    expect(instructionsFor(TOOL_ORDER)).not.toMatch(/:\/\/|www\.|http/i);
    expect(INSTRUCTIONS).toContain('mti:are-we-affected');
    expect(INSTRUCTIONS).toContain('mti:safe-install');
  });
});
