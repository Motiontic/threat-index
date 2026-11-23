import { describe, expect, it } from 'vitest';
import { ApiConflict, ApiUnavailable, createAccountClient, SignInRequired } from '../app/data/api.server';
import { resetFixtureAccounts } from '../app/data/fixture-account.server';
import { fixtureApi } from '../app/data/fixture-api.server';
import type { AccountClient } from '../app/data/types';
import { DELETE_PHRASE, handleAccountAction, savedSearchBody } from '../app/lib/account-action.server';

const ORIGIN = 'https://site.test';
const UUID = '123e4567-e89b-12d3-a456-426614174000';

function recorder(overrides: Partial<AccountClient> = {}) {
  const calls: [string, ...unknown[]][] = [];
  const rec =
    (name: string, ret: unknown = {}) =>
    async (...args: unknown[]) => {
      calls.push([name, ...args]);
      return ret;
    };
  const client = {
    me: rec('me'),
    patchMe: rec('patchMe', { userId: 'u' }),
    watchList: rec('watchList'),
    watch: rec('watch', { entryKey: 'CVE-2025-1', alertsOn: true }),
    unwatch: rec('unwatch'),
    savedList: rec('savedList'),
    saveSearch: rec('saveSearch', { name: 'saved' }),
    deleteSearch: rec('deleteSearch'),
    deleteAccount: rec('deleteAccount'),
    entryFull: rec('entryFull'),
    ...overrides,
  } as unknown as AccountClient;
  return { client, calls };
}

function post(
  fields: Record<string, string | undefined>,
  headers: Record<string, string> = { Origin: ORIGIN },
) {
  return new Request(`${ORIGIN}/account/do`, {
    method: 'POST',
    headers,
    body: new URLSearchParams(
      Object.entries(fields).filter((e): e is [string, string] => e[1] !== undefined),
    ),
  });
}
const run = (req: Request, client: AccountClient | null) =>
  handleAccountAction(req, { getClient: async () => client });

describe('account/do guards', () => {
  it('rejects a foreign Origin with 403, a missing Origin with 403, before anything else', async () => {
    const { client, calls } = recorder();
    for (const headers of [
      { Origin: 'https://evil.test' } as Record<string, string>,
      {} as Record<string, string>,
      { Origin: 'null' },
      { Origin: `${ORIGIN}.evil.test` },
    ]) {
      expect(await run(post({ intent: 'watch', id: 'CVE-1' }, headers), client)).toMatchObject({
        ok: false,
        status: 403,
      });
    }
    expect(calls).toEqual([]);
  });

  it('rejects the Origin check even when signed out (403, not 401)', async () => {
    expect(
      await run(post({ intent: 'watch', id: 'CVE-1' }, { Origin: 'https://evil.test' }), null),
    ).toMatchObject({ status: 403 });
  });

  it('answers 401 with no session', async () => {
    expect(await run(post({ intent: 'watch', id: 'CVE-1' }), null)).toEqual({
      ok: false,
      error: 'sign_in_required',
      status: 401,
    });
  });

  it('answers 405 to anything but POST', async () => {
    const res = await run(
      new Request(`${ORIGIN}/account/do`, { method: 'GET', headers: { Origin: ORIGIN } }),
      recorder().client,
    );
    expect(res).toMatchObject({ ok: false, status: 405 });
  });

  it('rejects an unknown or missing intent', async () => {
    const { client, calls } = recorder();
    expect(await run(post({ intent: 'nuke' }), client)).toMatchObject({
      status: 400,
      error: 'unknown_intent',
    });
    expect(await run(post({}), client)).toMatchObject({ status: 400 });
    expect(calls).toEqual([]);
  });
});

describe('intent validation', () => {
  it('profile: validates name, digest and weekday, then patches', async () => {
    const { client, calls } = recorder();
    const ok = {
      intent: 'profile',
      displayName: ' Ada ',
      instant: 'on',
      digest: 'weekly',
      digestWeekday: '3',
    };
    expect(await run(post(ok), client)).toMatchObject({ ok: true });
    expect(calls[0]).toEqual([
      'patchMe',
      { displayName: 'Ada', alerts: { instant: true, digest: 'weekly', digestWeekday: 3 } },
    ]);
    // The checkbox is absent when off; an empty name clears it.
    await run(post({ ...ok, instant: '', displayName: '' }), client);
    delete (ok as Record<string, string>).instant;
    await run(post(ok), client);
    expect(calls[1]?.[1]).toMatchObject({ displayName: null, alerts: { instant: false } });
    expect(calls[2]?.[1]).toMatchObject({ alerts: { instant: false } });
    const before = calls.length;
    for (const bad of [
      { ...ok, displayName: 'a'.repeat(81) },
      { ...ok, displayName: 'bad\u0000name' },
      { ...ok, displayName: 'bad\nname' },
      { ...ok, digest: 'hourly' },
      { ...ok, digest: '' },
      { ...ok, digestWeekday: '7' },
      { ...ok, digestWeekday: '-1' },
      { ...ok, digestWeekday: '1.5' },
      { ...ok, digestWeekday: '' },
      { ...ok, digestWeekday: 'x' },
    ]) {
      expect(await run(post(bad), client), JSON.stringify(bad)).toMatchObject({ ok: false, status: 400 });
    }
    expect(calls.length).toBe(before);
  });

  it('watch, unwatch, watch-alerts: ids must match the entry pattern; alertsOn must be a boolean string', async () => {
    const { client, calls } = recorder();
    expect(await run(post({ intent: 'watch', id: 'CVE-2025-1' }), client)).toMatchObject({ ok: true });
    expect(await run(post({ intent: 'unwatch', id: 'CVE-2025-1' }), client)).toMatchObject({ ok: true });
    expect(
      await run(post({ intent: 'watch-alerts', id: 'CVE-2025-1', alertsOn: 'false' }), client),
    ).toMatchObject({ ok: true });
    expect(calls.map((c) => c[0])).toEqual(['watch', 'unwatch', 'watch']);
    expect(calls[2]).toEqual(['watch', 'CVE-2025-1', false]);
    const before = calls.length;
    for (const f of [
      { intent: 'watch', id: '' },
      { intent: 'watch' },
      { intent: 'watch', id: 'a/b' },
      { intent: 'watch', id: '../x' },
      { intent: 'watch', id: 'a b' },
      { intent: 'unwatch', id: 'x'.repeat(101) },
      { intent: 'watch-alerts', id: 'CVE-1', alertsOn: 'yes' },
      { intent: 'watch-alerts', id: 'CVE-1' },
    ]) {
      expect(await run(post(f), client), JSON.stringify(f)).toMatchObject({ ok: false, status: 400 });
    }
    expect(calls.length).toBe(before);
  });

  it('save-search: rebuilds the body from the query string and validates the name', async () => {
    const { client, calls } = recorder();
    await run(
      post({ intent: 'save-search', qs: '?q=log4j&type=vuln&sig=kev&sev=high&year=2021&sort=new&junk=1' }),
      client,
    );
    expect(calls[0]).toEqual([
      'saveSearch',
      {
        name: 'log4j',
        query: 'log4j',
        params: { type: ['vuln'], sig: ['kev'], sev: ['high'], year: ['2021'], sort: 'new' },
      },
    ]);
    await run(post({ intent: 'save-search', qs: '?sig=kev', name: 'KEV list' }), client);
    expect(calls[1]).toEqual(['saveSearch', { name: 'KEV list', query: '', params: { sig: ['kev'] } }]);
    const long = 'q'.repeat(200);
    await run(post({ intent: 'save-search', qs: `?q=${long}` }), client);
    expect(calls[2]?.[1]).toMatchObject({ name: 'q'.repeat(80) });
    const before = calls.length;
    for (const f of [
      { intent: 'save-search', qs: '?q=a', name: 'n'.repeat(81) },
      { intent: 'save-search', qs: '?q=a', name: 'bad\u0007' },
      { intent: 'save-search', qs: `?q=${'a'.repeat(700)}` },
      { intent: 'save-search' },
    ]) {
      expect(await run(post(f), client), JSON.stringify(f)).toMatchObject({ ok: false, status: 400 });
    }
    expect(calls.length).toBe(before);
    expect(savedSearchBody('', '').name).toBe('Saved search');
  });

  it('delete-search: needs a UUID', async () => {
    const { client, calls } = recorder();
    expect(await run(post({ intent: 'delete-search', id: UUID }), client)).toMatchObject({ ok: true });
    for (const id of ['', 'abc', 'CVE-1', `${UUID}x`]) {
      expect(await run(post({ intent: 'delete-search', id }), client)).toMatchObject({
        ok: false,
        status: 400,
      });
    }
    expect(calls).toHaveLength(1);
  });

  it('delete-account: re-checks the typed phrase exactly', async () => {
    const { client, calls } = recorder();
    for (const confirm of [
      '',
      'delete my account ',
      'Delete my account',
      'delete account',
      ' delete my account',
    ]) {
      expect(await run(post({ intent: 'delete-account', confirm }), client), confirm).toMatchObject({
        ok: false,
        status: 400,
        error: 'confirmation_mismatch',
      });
    }
    expect(await run(post({ intent: 'delete-account' }), client)).toMatchObject({ ok: false });
    expect(calls).toEqual([]);
    expect(await run(post({ intent: 'delete-account', confirm: DELETE_PHRASE }), client)).toMatchObject({
      ok: true,
    });
    expect(calls).toEqual([['deleteAccount']]);
  });
});

describe('API errors', () => {
  it('maps them to statuses and codes', async () => {
    const cases: [Error, number, string][] = [
      [new SignInRequired(), 401, 'sign_in_required'],
      [new ApiConflict('limit_reached'), 409, 'limit_reached'],
      [new ApiUnavailable('down'), 502, 'unavailable'],
    ];
    for (const [err, status, error] of cases) {
      const { client } = recorder({
        watch: async () => {
          throw err;
        },
      });
      expect(await run(post({ intent: 'watch', id: 'CVE-1' }), client)).toEqual({ ok: false, error, status });
    }
  });

  it('tells a failed sign-in removal (API 502) from any other unavailable on delete', async () => {
    const fail = (e: Error) =>
      recorder({
        deleteAccount: async () => {
          throw e;
        },
      }).client;
    const body = { intent: 'delete-account', confirm: DELETE_PHRASE };
    expect(await run(post(body), fail(new ApiUnavailable('x', { status: 502 })))).toMatchObject({
      status: 502,
      error: 'delete_sign_in_failed',
    });
    expect(await run(post(body), fail(new ApiUnavailable('timeout')))).toMatchObject({
      status: 502,
      error: 'unavailable',
    });
  });
});

describe('against the fixture account API', () => {
  const api = {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => fixtureApi(new Request(input, init)),
  };
  const as = (user: string) => createAccountClient(api, `fake.${user}`);

  it('watches, toggles alerts, saves, deletes, and keeps users apart', async () => {
    resetFixtureAccounts();
    const ada = as('ada');
    await run(post({ intent: 'watch', id: 'cve-2025-3248' }), ada);
    expect((await ada.watchList()).items.map((i) => i.entryKey)).toEqual(['CVE-2025-3248']);
    await run(post({ intent: 'watch-alerts', id: 'CVE-2025-3248', alertsOn: 'false' }), ada);
    expect((await ada.watchList()).items[0]?.alertsOn).toBe(false);
    expect((await as('bob').watchList()).items).toEqual([]);
    await run(post({ intent: 'save-search', qs: '?q=log4j&type=vuln' }), ada);
    const saved = (await ada.savedList()).items;
    expect(saved).toHaveLength(1);
    await run(post({ intent: 'delete-search', id: saved[0]?.id ?? '' }), ada);
    expect((await ada.savedList()).items).toEqual([]);
    await run(post({ intent: 'unwatch', id: 'CVE-2025-3248' }), ada);
    expect((await ada.watchList()).items).toEqual([]);
    expect(await run(post({ intent: 'watch', id: 'CVE-0000-0' }), ada)).toMatchObject({ status: 404 });
    await run(post({ intent: 'delete-account', confirm: DELETE_PHRASE }), ada);
    expect((await ada.me()).displayName).toBeNull();
  });

  it('rejects a token that is not a fake one, and serves the full entry only to a fake token', async () => {
    expect(
      await createAccountClient(api, 'real.jwt')
        .me()
        .catch((e) => e),
    ).toBeInstanceOf(SignInRequired);
    const full = await as('ada').entryFull('CVE-2025-3248');
    expect(full?.signals.map((s) => s.kind)).toEqual(
      expect.arrayContaining(['exploited_wild', 'ransomware', 'public_exploit', 'poc', 'detection']),
    );
    const pub = await api.fetch(new Request('https://ti-api.internal/v1/entries/CVE-2025-3248'));
    expect(((await pub.json()) as { access: string }).access).toBe('preview');
  });

  it('limits watch items and saved searches like the API (409 limit_reached)', async () => {
    resetFixtureAccounts();
    const c = as('lim');
    for (let i = 0; i < 50; i++) await c.saveSearch({ name: `s${i}`, query: `q${i}` });
    await expect(c.saveSearch({ name: 'one more', query: 'x' })).rejects.toMatchObject({
      error: 'limit_reached',
    });
  });
});
