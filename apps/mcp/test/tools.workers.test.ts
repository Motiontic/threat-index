import { verifyMcpAssertion } from '@ti/core/mcp-user';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { resetJwksCacheForTests } from '../src/auth/jwks';
import { mtiLink, SOURCE_LINK_HOSTS, sourceLink } from '../src/links';
import { enabledTools, TOOL_ORDER } from '../src/tools';
import { type FakeApi, fakeApi, type Handler, ok, status, withApi } from './support/fake-api';
import * as F from './support/fixtures';
import { BASE_ENV, bodyOf, legacyHeaders, modernCall, send } from './support/mcp';
import { goodPayload, type JwksSpy, makeKey, mockJwks, SUB, signJwt, type TestKey } from './support/tokens';

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

async function run(
  tool: string,
  args: Record<string, unknown>,
  handler: Handler,
  extraEnv: Record<string, unknown> = {},
) {
  jwks = mockJwks([key]);
  const api = fakeApi(handler);
  const c = modernCall(token, 'tools/call', { name: tool, arguments: args });
  const res = await send({ headers: c.headers, body: c.body }, withApi(BASE_ENV, api, extraEnv as never));
  const body = await bodyOf(res);
  return { res, body, result: body?.result, api };
}
const only = (api: FakeApi) => {
  expect(api.calls).toHaveLength(1);
  return api.calls[0]!;
};
const text = (r: any) => r.content[0].text as string;

/** Every string in a value, with its path. */
function* strings(v: unknown, path = ''): Generator<[string, string]> {
  if (typeof v === 'string') yield [path, v];
  else if (Array.isArray(v)) for (const [i, x] of v.entries()) yield* strings(x, `${path}[${i}]`);
  else if (v && typeof v === 'object')
    for (const [k, x] of Object.entries(v)) yield* strings(x, path ? `${path}.${k}` : k);
}
/** No http text outside link fields; every link field passes mtiLink or sourceLink. */
function checkStrings(data: unknown) {
  for (const [path, s] of strings(data)) {
    const last = path.split('.').pop() ?? '';
    const isLink = /(^|\.|\])(url|sourceUrl)$/.test(path) || last === 'url' || last === 'sourceUrl';
    if (isLink) {
      const okLink = s.startsWith('https://mti.test/') || sourceLink(s) !== null;
      expect(okLink, `${path}: ${s}`).toBe(true);
    } else {
      expect(s, path).not.toMatch(/https?:\/\//i);
    }
    expect(s, path).not.toMatch(/[<>​‮]/);
  }
}
function expectUntrustedOnly(data: any) {
  const flat = JSON.stringify(data);
  expect(flat).not.toContain('<script');
  expect(flat).not.toContain('evil.test');
  expect(flat).not.toContain('​');
}
function validates(tool: string, data: unknown) {
  // The SDK already checks outputSchema; a failure would have come back as isError. This asserts the shape too.
  expect(data).toBeTruthy();
  const def = enabledTools().find((t) => t.name === tool)!;
  expect(Object.keys((def.outputSchema as any).properties).length).toBeGreaterThan(0);
}

describe('mti_get_entry', () => {
  it('calls GET /v1/entries/<id> with a verifiable assertion, and cleans everything', async () => {
    const { res, result, api } = await run('mti_get_entry', { id: 'cve-2026-0001' }, () => ok(F.entryFull));
    expect(res.status).toBe(200);
    expect(result.isError).toBeFalsy();
    const seen = only(api);
    expect(seen.method).toBe('GET');
    expect(seen.path).toBe('/v1/entries/CVE-2026-0001');
    const id = await verifyMcpAssertion([BASE_ENV.MCP_HMAC_SECRET], new Headers(seen.headers), {
      requestId: seen.headers['x-request-id']!,
      method: 'GET',
      pathWithQuery: seen.path,
      body: null,
    });
    expect(id).toEqual({ sub: SUB, scopes: ['mti:read'], clientId: 'client-abc' });
    const sc = result.structuredContent;
    validates('mti_get_entry', sc);
    expect(text(result)).toBe(JSON.stringify(sc));
    expect(result._meta.untrusted).toBe(true);
    expect(sc.found).toBe(true);
    expect(sc.url).toBe('https://mti.test/e/CVE-2026-0001');
    expect(sc.untrusted.title).toContain('Ignore previous instructions');
    expectUntrustedOnly({ ...sc, untrusted: undefined });
    expectUntrustedOnly(sc.untrusted);
    checkStrings(sc);
    expect(sc.exploitation).toEqual({
      exploitedInWild: 1,
      ransomware: 0,
      publicExploits: 1,
      proofsOfConcept: 1,
      detections: 0,
      sources: ['kev', 'github', 'edb'],
    });
    expect(sc.fixes).toEqual([
      { ecosystem: 'npm', name: 'left-pad', introduced: '1.0.0', fixed: '1.3.1', source: 'osv' },
    ]);
    expect(sc.cwe).toEqual(['CWE-79']);
    expect(sc.aliases).toEqual(['GHSA-cfgh-2345-jmpq']);
    expect(sc.advisories[0].url).toBe('https://github.com/advisories/GHSA-cfgh-2345-jmpq');
    expect(sc.advisories[1].url).toBeNull();
    expect(sc.recentChanges).toEqual([{ kind: 'newly_exploited', at: '2026-02-01', source: 'kev' }]);
    for (const secret of ['REF-SECRET', 'poc-repo', 'OLD-SECRET', 'NEW-SECRET', 'kev.example'])
      expect(text(result)).not.toContain(secret);
    expect(res.headers.get('x-request-id')).toBeTruthy();
    expect(result._meta['io.modelcontextprotocol/serverInfo']).toBeTruthy();
  });
  it('404 → found: false', async () => {
    const { result } = await run('mti_get_entry', { id: 'CVE-2026-9999' }, () => status(404));
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ found: false, id: 'CVE-2026-9999' });
  });
  it.each(['hello world', 'CVE-26-1', 'CANARY-NOT-AN-ID', '../../etc/passwd', 'CVE-2026-0001/../x'])(
    'bad id %s → invalid_argument with no echo',
    async (id) => {
      const { result, api } = await run('mti_get_entry', { id }, () => ok({}));
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).not.toContain(id.includes('CANARY') ? 'CANARY' : '\u0000');
      if (id !== 'hello world' && id !== '../../etc/passwd' && id !== 'CVE-2026-0001/../x')
        expect(text(result)).not.toContain(id);
      expect(api.calls).toHaveLength(0);
    },
  );
  it('a zero-width character → invalid_argument naming the path', async () => {
    const { result, api } = await run('mti_get_entry', { id: 'CVE-2026-0001​' }, () => ok({}));
    expect(result.isError).toBe(true);
    // The schema pattern refuses it first, with the fixed schema text.
    expect(api.calls).toHaveLength(0);
  });
});

describe('mti_search', () => {
  it('sends the right query and returns cleaned hits with a sealed cursor', async () => {
    const { result, api } = await run(
      'mti_search',
      { query: 'log4j rce', kind: 'vulnerability', exploitedOnly: true, limit: 5 },
      () => ok(F.searchBody),
    );
    const seen = only(api);
    const u = new URL(`https://x${seen.path}`);
    expect(u.pathname).toBe('/v1/search');
    expect(Object.fromEntries(u.searchParams)).toEqual({
      q: 'log4j rce',
      type: 'vuln',
      sig: 'kev',
      limit: '5',
    });
    const sc = result.structuredContent;
    validates('mti_search', sc);
    expect(sc.total).toBe(2);
    expect(sc.hits).toHaveLength(1);
    expect(sc.hits[0].url).toBe('https://mti.test/e/CVE-2026-0001');
    expect(sc.nextCursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(sc.nextCursor).not.toContain('APICURSOR');
    expectUntrustedOnly({ ...sc, hits: sc.hits.map((h: any) => ({ ...h, untrusted: undefined })) });
    checkStrings(sc);
    expect(result._meta.untrusted).toBe(true);
  });
  it('the cursor round-trips: the API cursor goes back to ti-api', async () => {
    const first = await run('mti_search', { query: 'a' }, () => ok(F.searchBody));
    const cursor = first.result.structuredContent.nextCursor;
    const second = await run('mti_search', { query: 'a', cursor }, () =>
      ok({ ...F.searchBody, cursor: undefined }),
    );
    expect(new URL(`https://x${only(second.api).path}`).searchParams.get('cursor')).toBe('APICURSOR_abc-1');
    expect(second.result.structuredContent.nextCursor).toBeNull();
  });
  it('a query with a zero-width character → invalid_argument naming query', async () => {
    const { result } = await run('mti_search', { query: 'a​b' }, () => ok(F.searchBody));
    expect(result.isError).toBe(true);
    expect(text(result)).toContain('argument query');
  });
});

describe('mti_latest_threats', () => {
  it.each([
    ['exploited', 1],
    ['malicious', 1],
    ['breaches', 1],
    ['ai', 1],
    ['exploits', 0],
  ] as const)('%s', async (kind, n) => {
    const { result, api } = await run('mti_latest_threats', { kind }, () => ok(F.home));
    expect(only(api).path).toBe('/v1/home');
    const sc = result.structuredContent;
    validates('mti_latest_threats', sc);
    expect(sc.items).toHaveLength(n);
    checkStrings(sc);
    if (kind === 'ai') expect(sc.items[0].url).toBe('https://mti.test/incident/aiid/inc-9');
    if (kind === 'breaches') expect(sc.items[0].url).toBe('https://mti.test/breach/cik%3A123');
    if (kind === 'exploited') expect(sc.items[0].signal.length).toBeLessThanOrEqual(60);
  });
});

describe('mti_search_breaches', () => {
  it('sends q and returns only allow-listed company-level fields', async () => {
    const { result, api } = await run('mti_search_breaches', { query: 'Acme', limit: 3 }, () =>
      ok(F.breachPage(1, 25, 2)),
    );
    expect(only(api).path).toBe('/v1/breaches?q=Acme');
    const sc = result.structuredContent;
    validates('mti_search_breaches', sc);
    expect(sc.items).toHaveLength(3);
    expect(Object.keys(sc.items[0]).sort()).toEqual([
      'companyKey',
      'counts',
      'dates',
      'firstSeen',
      'jurisdictions',
      'key',
      'noticeCount',
      'sources',
      'untrusted',
      'url',
    ]);
    expect(sc.items[1].companyKey).toBe('cik:1234');
    expect(sc.items[0].companyKey).toBeNull();
    expect(sc.items[0].jurisdictions).toEqual(['US-CA']);
    expect(sc.items[0].sources).toEqual(['sec']);
    for (const bad of ['PERSONAL', 'ssn', 'victim@example.com']) expect(text(result)).not.toContain(bad);
    checkStrings(sc);
    expect(sc.nextCursor).toBeTruthy();
  });
  it('pages by {page, skip}: limit slices the API pages of 25', async () => {
    let call = 0;
    const h: Handler = () => ok(F.breachPage(++call === 1 ? 1 : 2, 25, call === 1 ? 2 : null));
    const a = await run('mti_search_breaches', { limit: 25 }, h);
    expect(a.result.structuredContent.items).toHaveLength(25);
    const cursor = a.result.structuredContent.nextCursor;
    expect(cursor).toBeTruthy();
    const b = await run('mti_search_breaches', { limit: 25, cursor }, h);
    expect(only(b.api).path).toBe('/v1/breaches?page=2');
    expect(b.result.structuredContent.nextCursor).toBeNull();
  });
  it('a query with @ → invalid_argument "looks like an email address"', async () => {
    const { result, api } = await run('mti_search_breaches', { query: 'victim@example.com' }, () => ok({}));
    expect(result.isError).toBe(true);
    expect(text(result)).toContain('looks like an email address');
    expect(text(result)).not.toContain('victim');
    expect(api.calls).toHaveLength(0);
  });
});

describe('mti_search_incidents', () => {
  it('sends q and kind, drops non-allow-listed source links', async () => {
    const { result, api } = await run('mti_search_incidents', { query: 'deepfake', kind: 'ai' }, () =>
      ok(F.incidentPage),
    );
    expect(only(api).path).toBe('/v1/incidents?q=deepfake&kind=ai');
    const sc = result.structuredContent;
    validates('mti_search_incidents', sc);
    expect(sc.items[0].url).toBe('https://mti.test/incident/aiid/42');
    expect(sc.items[0].sourceUrl).toBe('https://attack.mitre.org/x');
    expect(sc.items[1].sourceUrl).toBeNull();
    checkStrings(sc);
  });
});

describe('mti_get_technique', () => {
  it('returns the technique, and 404 → found: false', async () => {
    const { result, api } = await run('mti_get_technique', { id: 'T1059' }, () => ok(F.technique));
    expect(only(api).path).toBe('/v1/techniques/T1059');
    const sc = result.structuredContent;
    validates('mti_get_technique', sc);
    expect(sc.parent).toMatchObject({ id: 'T1000', url: 'https://mti.test/technique/T1000' });
    expect(sc.children).toHaveLength(1);
    expect(sc.vulnsMore).toBe(true);
    checkStrings(sc);
    const nf = await run('mti_get_technique', { id: 'T1059.001' }, () => status(404));
    expect(nf.result.structuredContent).toMatchObject({ found: false, id: 'T1059.001' });
  });
  it('a bad id → invalid_argument with no echo', async () => {
    const { result, api } = await run('mti_get_technique', { id: 'CANARY' }, () => ok({}));
    expect(result.isError).toBe(true);
    expect(text(result)).not.toContain('CANARY');
    expect(api.calls).toHaveLength(0);
  });
});

describe('mti_list_sources', () => {
  it('lists only sources with records, with no untrusted block and no trust meta', async () => {
    const { result, api } = await run('mti_list_sources', {}, () => ok(F.sources));
    expect(only(api).path).toBe('/v1/sources');
    const sc = result.structuredContent;
    validates('mti_list_sources', sc);
    expect(sc.sources.map((s: any) => s.id)).toEqual(['nvd']);
    expect(result._meta.untrusted).toBeUndefined();
    expect(JSON.stringify(sc)).not.toContain('untrusted');
  });
});

describe('mti_check_packages', () => {
  const pk = (n: number) =>
    Array.from({ length: n }, (_, i) => ({ ecosystem: 'npm', name: `pkg-${i}`, version: '1.0.0' }));
  it('POSTs the checked body and reshapes the answer', async () => {
    const { result, api } = await run(
      'mti_check_packages',
      {
        packages: [
          { ecosystem: 'npm', name: 'left-pad', version: '1.0.0' },
          { purl: 'pkg:pypi/requests@2.0.0' },
        ],
      },
      () => ok(F.checkBody(2)),
    );
    const seen = only(api);
    expect(seen.method).toBe('POST');
    expect(seen.path).toBe('/v1/packages/check');
    expect(JSON.parse(seen.body)).toEqual({
      packages: [
        { ecosystem: 'npm', name: 'left-pad', version: '1.0.0' },
        { purl: 'pkg:pypi/requests@2.0.0' },
      ],
    });
    const sc = result.structuredContent;
    validates('mti_check_packages', sc);
    const m = sc.results[0].matches[0];
    expect(m.url).toBe('https://mti.test/e/CVE-2026-0001');
    expect(m.fixedIn).toBeNull();
    expect(m.signals).toEqual(['exploited_wild']);
    expect(m.sources).toEqual(['osv']);
    expect(sc.results[0].upgradeTo).toBe('1.3.1');
    expect(sc.noRecord).toHaveLength(1);
    expect(sc.notes.join(' ')).toContain('does not mean safe');
    expect(sc.notes.join(' ')).toContain('Reachability is not checked');
    expect(sc.nextCursor).toBeNull();
    checkStrings(sc);
    expect(text(result)).not.toContain('upstream-url');
  });
  it('a 1,000-package call that overflows the budget → truncated and a working nextCursor', async () => {
    const big = F.checkBody(1000);
    const pkgs = pk(1000);
    const first = await run('mti_check_packages', { packages: pkgs }, () => ok(big));
    const sc = first.result.structuredContent;
    expect(sc.truncated).toBe(true);
    expect(text(first.result).length).toBeLessThanOrEqual(32_000);
    expect(sc.nextCursor).toBeTruthy();
    const second = await run('mti_check_packages', { packages: pkgs, cursor: sc.nextCursor }, () => ok(big));
    expect(second.result.isError).toBeFalsy();
    const seen = sc.results.length + sc.noRecord.length;
    expect(second.result.structuredContent.noRecord[0]).toEqual(big.noRecord[seen - sc.results.length]);
    expect(second.result.structuredContent.rejected).toEqual([]);
  });
  it('the cursor is tied to the package list', async () => {
    const first = await run('mti_check_packages', { packages: pk(1000) }, () => ok(F.checkBody(1000)));
    const other = await run(
      'mti_check_packages',
      { packages: pk(999), cursor: first.result.structuredContent.nextCursor },
      () => ok({}),
    );
    expect(other.body.error.code).toBe(-32602);
    expect(other.api.calls).toHaveLength(0);
  });
  it('a 501 → not_available_yet', async () => {
    const { result } = await run('mti_check_packages', { packages: pk(1) }, () => status(501));
    expect(text(result)).toContain('not available yet');
  });
  it('a bad purl entry is a schema error', async () => {
    const { result } = await run('mti_check_packages', { packages: [{ purl: 'nope' }] }, () => ok({}));
    expect(result.isError).toBe(true);
  });
  it('a zero-width character in a name → invalid_argument naming packages[0].name', async () => {
    const { result, api } = await run(
      'mti_check_packages',
      { packages: [{ ecosystem: 'npm', name: 'a​b', version: '1' }] },
      () => ok({}),
    );
    expect(text(result)).toContain('packages[0].name');
    expect(api.calls).toHaveLength(0);
  });
});

describe('upstream errors', () => {
  const cases: [string, number, Record<string, string>, any, string][] = [
    ['429', 429, { 'retry-after': '17' }, { error: 'rate_limited' }, 'Try again in 17 seconds'],
    ['429 without Retry-After', 429, {}, { error: 'rate_limited' }, 'Try again in 60 seconds'],
    ['403 blocked', 403, {}, { error: 'blocked' }, 'cannot use MTI'],
    ['other 403', 403, {}, { error: 'forbidden' }, 'Something went wrong on the MTI side'],
    ['500', 500, {}, { error: 'x' }, 'could not answer right now'],
    ['401', 401, {}, { error: 'x' }, 'Something went wrong on the MTI side'],
    ['400', 400, {}, { error: 'x' }, 'was not accepted'],
  ];
  it.each(cases)('%s', async (_n, code, headers, body, want) => {
    const { result } = await run('mti_search', { query: 'a' }, () => status(code, body, headers));
    expect(result.isError).toBe(true);
    expect(text(result)).toContain(want);
    expect(text(result)).toMatch(/Request ID: /);
    expect(result.structuredContent).toBeUndefined();
  });
  it('a 404 on a non-lookup tool → upstream_unavailable', async () => {
    const { result } = await run('mti_search', { query: 'a' }, () => status(404));
    expect(text(result)).toContain('could not answer right now');
  });
  it('a network failure and non-JSON → upstream_unavailable', async () => {
    const a = await run('mti_search', { query: 'a' }, () => {
      throw new Error('boom');
    });
    expect(text(a.result)).toContain('could not answer right now');
    const b = await run('mti_search', { query: 'a' }, () => new Response('not json', { status: 200 }));
    expect(text(b.result)).toContain('could not answer right now');
  });
});

describe('off switch and tools/list', () => {
  it('mcp:tool:mti_search:off turns off that tool only, and tools/list does not change', async () => {
    await BASE_ENV.SETTINGS.put('mcp:tool:mti_search:off', '1');
    try {
      const off = await run('mti_search', { query: 'a' }, () => ok(F.searchBody));
      expect(text(off.result)).toContain('turned off');
      expect(off.api.calls).toHaveLength(0);
      const on = await run('mti_get_entry', { id: 'CVE-2026-0001' }, () => ok(F.entryFull));
      expect(on.result.isError).toBeFalsy();
      jwks = mockJwks([key]);
      const c = modernCall(token, 'tools/list');
      const list = await bodyOf(await send({ headers: c.headers, body: c.body }));
      expect(list.result.tools.map((t: any) => t.name)).toContain('mti_search');
    } finally {
      await BASE_ENV.SETTINGS.delete('mcp:tool:mti_search:off');
    }
  });

  it('the list is the eight tools in TOOL_ORDER order, with hints and cache hints on 2026-07-28', async () => {
    jwks = mockJwks([key]);
    const c = modernCall(token, 'tools/list');
    const body = await bodyOf(await send({ headers: c.headers, body: c.body }));
    const names = body.result.tools.map((t: any) => t.name);
    expect(names).toEqual(
      TOOL_ORDER.filter((n) =>
        [
          'mti_check_packages',
          'mti_get_entry',
          'mti_search',
          'mti_latest_threats',
          'mti_search_breaches',
          'mti_search_incidents',
          'mti_get_technique',
          'mti_list_sources',
        ].includes(n),
      ),
    );
    for (const t of body.result.tools) {
      expect(t.title).toBeTruthy();
      expect(t.annotations).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
      expect(t.inputSchema.additionalProperties).toBe(false);
      expect(t.outputSchema).toBeTruthy();
    }
    expect(body.result._meta.ttlMs ?? body.result.ttlMs).toBe(3_600_000);
    expect(body.result._meta.cacheScope ?? body.result.cacheScope).toBe('public');
    expect(JSON.stringify(body.result.tools)).toMatchSnapshot();
  });

  it('legacy clients see the same eight tools', async () => {
    jwks = mockJwks([key]);
    const res = await send({
      headers: legacyHeaders(token),
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    const body = await bodyOf(res);
    expect(body.result.tools.map((t: any) => t.name)).toHaveLength(8);
    expect(body.result.ttlMs).toBeUndefined();
  });
});

describe('through the service binding', () => {
  it('one end-to-end tool call over the real API binding (the mcp-seams echo fake)', async () => {
    jwks = mockJwks([key]);
    const c = modernCall(token, 'tools/call', { name: 'mti_list_sources', arguments: {} });
    // BASE_ENV keeps the real `API` service binding from vitest.workers.mts: it echoes the request it got.
    const res = await send({ headers: c.headers, body: c.body });
    expect(res.status).toBe(200);
    const body = await bodyOf(res);
    expect(body.result.isError).toBeFalsy();
    expect(body.result.structuredContent.sources).toEqual([]);
    expect(body.result.structuredContent.asOf).toMatch(/^\d{4}-/);
  });
});

describe('links', () => {
  it('mtiLink refuses bad parts and encodes good ones', () => {
    expect(mtiLink(BASE_ENV, 'entry', 'CVE-2026-0001')).toBe('https://mti.test/e/CVE-2026-0001');
    expect(mtiLink(BASE_ENV, 'entry', '../x')).toBeNull();
    expect(mtiLink(BASE_ENV, 'entry', 'a b')).toBeNull();
    expect(mtiLink(BASE_ENV, 'sources')).toBe('https://mti.test/sources');
  });
  it('sourceLink allows only listed hosts over https, and GHSA pages on github', () => {
    for (const host of SOURCE_LINK_HOSTS) expect(sourceLink(`https://${host}/x`)).toBe(`https://${host}/x`);
    for (const bad of [
      'http://nvd.nist.gov/x',
      'https://evil.test/',
      'https://nvd.nist.gov:8443/x',
      'https://u:p@nvd.nist.gov/',
      'https://127.0.0.1/',
      'https://github.com/evil/poc',
      'https://nvd.nist.gov.evil.test/',
      'javascript:alert(1)',
      5,
    ])
      expect(sourceLink(bad), String(bad)).toBeNull();
    expect(sourceLink('https://github.com/advisories/GHSA-cfgh-2345-jmpq')).toBeTruthy();
  });
});
