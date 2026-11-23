import { describe, expect, it } from 'vitest';
import {
  ApiBadRequest,
  ApiConflict,
  ApiUnavailable,
  createAccountClient,
  NotFound,
  SignInRequired,
} from '../app/data/api.server';
import { guardEntryFull, guardMe, guardSavedSearch, guardWatchItem, safeUrl } from '../app/data/guards';
import { CREDIT, fakeApi, PREVIEW } from './fake-api';

const ME = {
  userId: 'user_1',
  email: 'a@b.test',
  displayName: null,
  alerts: { instant: true, digest: 'weekly', digestWeekday: 1 },
};
const WATCH = { entryKey: 'CVE-2025-1', title: 'T', alertsOn: true, createdAt: '2025-01-01T00:00:00Z' };
const SAVED = {
  id: 'a'.repeat(8) + '-aaaa-aaaa-aaaa-' + 'a'.repeat(12),
  name: 'n',
  query: 'q',
  params: {},
  alertsOn: false,
  createdAt: 'x',
};
const FULL = {
  access: 'full',
  entry: {
    ...PREVIEW,
    cwe: ['CWE-1'],
    advisories: [
      {
        source: 'a',
        sourceId: '1',
        status: 'ok',
        url: 'javascript:alert(1)',
        display: 'full',
        affected: [{ ecosystem: 'npm', name: 'x' }],
      },
      {
        source: 'b',
        sourceId: '2',
        status: 'SECRET',
        url: 'https://b.test/2',
        display: 'link',
        published: '2025',
        affected: [{ ecosystem: 'npm', name: 'leak' }],
      },
      { source: 'c', sourceId: '3', status: 'x', url: 'https://c.test/', display: 'hidden' },
    ],
    signals: [
      { kind: 'poc', source: 's', ref: 'r', firstSeen: '2025-01-01', url: 'data:text/html,x' },
      { kind: 'poc', source: 's', ref: 'r2', firstSeen: '2025-01-01', url: 'https://ok.test/p' },
    ],
    changes: [{ kind: 'cvss', old: '1', new: '2', at: '2025-01-02' }],
    internalNote: 'must not pass',
  },
};

const client = (routes: Parameters<typeof fakeApi>[0], token = 'tok.en') => {
  const f = fakeApi(routes);
  return { ...f, client: createAccountClient(f.api, token, { requestId: 'req-test-0001', ip: null }) };
};

describe('account client requests', () => {
  it('sends Authorization: Bearer and JSON, and never a Cookie or visitor header', async () => {
    const { client: c, requests } = client({
      '/v1/me': { body: ME },
      '/v1/me/watch': { body: { items: [WATCH], limit: 1000 } },
      '/v1/me/watch/CVE-2025-1': { body: WATCH },
      '/v1/me/saved-searches': { status: 201, body: SAVED },
      '/v1/entries/CVE-2025-1': { body: FULL },
    });
    await c.me();
    await c.patchMe({ displayName: 'x' });
    await c.watchList();
    await c.watch('CVE-2025-1', false);
    await c.unwatch('CVE-2025-1');
    await c.saveSearch({ name: 'n', query: 'q' });
    await c.entryFull('CVE-2025-1');
    expect(requests.map((r) => `${r.method} ${new URL(r.url).pathname}`)).toEqual([
      'GET /v1/me',
      'PATCH /v1/me',
      'GET /v1/me/watch',
      'PUT /v1/me/watch/CVE-2025-1',
      'DELETE /v1/me/watch/CVE-2025-1',
      'POST /v1/me/saved-searches',
      'GET /v1/entries/CVE-2025-1',
    ]);
    for (const r of requests) {
      expect(r.headers.get('authorization')).toBe('Bearer tok.en');
      expect(r.headers.get('cookie')).toBeNull();
      expect([...r.headers.keys()].sort()).toEqual(
        [
          'accept',
          'authorization',
          'x-request-id',
          ...(r.method === 'PATCH' || r.method === 'PUT' || r.method === 'POST' ? ['content-type'] : []),
        ].sort(),
      );
      expect(r.signal).toBeDefined();
    }
    expect(await requests[1]?.clone().json()).toEqual({ displayName: 'x' });
    expect(await requests[3]?.clone().json()).toEqual({ alertsOn: false });
  });

  it('encodes ids in the path', async () => {
    const { client: c, requests } = client({ '/v1/me/watch/a%2Fb': { body: WATCH } });
    await c.watch('a/b');
    expect(new URL(requests[0]?.url ?? '').pathname).toBe('/v1/me/watch/a%2Fb');
  });
});

describe('account client status mapping', () => {
  it('maps 401 to SignInRequired', async () => {
    const { client: c } = client({ '/v1/me': { status: 401, body: { error: 'sign_in_required' } } });
    await expect(c.me()).rejects.toBeInstanceOf(SignInRequired);
  });
  it('maps 409 to ApiConflict with the API error', async () => {
    const { client: c } = client({ '/v1/me/watch/CVE-1': { status: 409, body: { error: 'limit_reached' } } });
    await expect(c.watch('CVE-1')).rejects.toMatchObject({ name: 'ApiConflict', error: 'limit_reached' });
    await expect(c.watch('CVE-1')).rejects.toBeInstanceOf(ApiConflict);
  });
  it('maps 400 to ApiBadRequest', async () => {
    const { client: c } = client({ '/v1/me': { status: 400, body: { error: 'bad_request' } } });
    await expect(c.patchMe({})).rejects.toBeInstanceOf(ApiBadRequest);
  });
  it('maps 404 to null for reads and NotFound for mutations', async () => {
    const { client: c } = client({});
    expect(await c.entryFull('CVE-9')).toBeNull();
    await expect(c.unwatch('CVE-9')).rejects.toBeInstanceOf(NotFound);
    await expect(c.deleteSearch('x')).rejects.toBeInstanceOf(NotFound);
    await expect(c.watch('CVE-9')).rejects.toBeInstanceOf(NotFound);
  });
  it('maps everything else, a network error and a bad body to ApiUnavailable', async () => {
    for (const route of [
      { status: 500, body: {} },
      { status: 502, body: { error: 'clerk_delete_failed' } },
      { throws: new Error('down') },
      { text: 'not json' },
      { body: { nonsense: true } },
    ]) {
      const { client: c } = client({ '/v1/me': route });
      await expect(c.me()).rejects.toBeInstanceOf(ApiUnavailable);
    }
    const { client: c } = client({ '/v1/me': { status: 502, body: {} } });
    await expect(c.deleteAccount()).rejects.toMatchObject({ status: 502 });
  });
  it('rejects an oversized body', async () => {
    const { client: c } = client({
      '/v1/me': { headers: { 'content-length': String(3 * 1024 * 1024) }, body: ME },
    });
    await expect(c.me()).rejects.toBeInstanceOf(ApiUnavailable);
  });
  it('returns null from entryFull when the API still answers preview', async () => {
    const { client: c } = client({
      '/v1/entries/CVE-2025-1': { body: { access: 'preview', entry: PREVIEW } },
    });
    expect(await c.entryFull('CVE-2025-1')).toBeNull();
  });
});

describe('guards', () => {
  it('drops javascript: and data: links, keeps http(s)', () => {
    expect(safeUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeUrl('data:text/html,x')).toBeUndefined();
    expect(safeUrl('//evil.test')).toBeUndefined();
    expect(safeUrl('not a url')).toBeUndefined();
    expect(safeUrl('https://a.test/x')).toBe('https://a.test/x');
    expect(safeUrl('http://a.test/')).toBe('http://a.test/');
  });

  it('cuts the full entry: no unsafe links, no hidden advisories, link ones keep only source, id and URL', () => {
    const full = guardEntryFull(FULL);
    expect(full).not.toBeNull();
    expect(full?.advisories.map((a) => a.source)).toEqual(['a', 'b']);
    expect(full?.advisories[0]).not.toHaveProperty('url');
    expect(full?.advisories[1]).toEqual({
      source: 'b',
      sourceId: '2',
      status: '',
      display: 'link',
      url: 'https://b.test/2',
    });
    expect(full?.signals[0]).not.toHaveProperty('url');
    expect(full?.signals[1]?.url).toBe('https://ok.test/p');
    expect(JSON.stringify(full)).not.toMatch(/javascript:|data:text|leak|SECRET|internalNote/);
  });

  it('answers null for a preview body', () => {
    expect(guardEntryFull({ access: 'preview', entry: PREVIEW })).toBeNull();
  });

  it('checks required fields and copies only known ones', () => {
    expect(guardMe({ ...ME, extra: 1 })).toEqual(ME);
    expect(() => guardMe({ ...ME, alerts: { instant: true, digest: 'hourly', digestWeekday: 1 } })).toThrow();
    expect(() => guardMe({ ...ME, alerts: { instant: true, digest: 'daily', digestWeekday: 9 } })).toThrow();
    expect(() => guardWatchItem({ ...WATCH, alertsOn: 'yes' })).toThrow();
    expect(guardSavedSearch({ ...SAVED, params: { type: ['vuln'], sort: 'new', junk: 1 } }).params).toEqual({
      type: ['vuln'],
      sort: 'new',
    });
    expect(CREDIT.sourceId).toBeTruthy();
  });
});
