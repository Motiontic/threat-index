import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  authMode,
  FAKE_COOKIE,
  fakeAuthActive,
  fakeSignInCookie,
  fakeSignOutCookie,
  readFakeUser,
  resetFakeAuthWarning,
} from '../app/lib/fake-auth.server';
import { localPath } from '../app/lib/redirect';

const api = { fetch: async () => new Response() } as unknown as Fetcher;
const KEY = `pk_test_${btoa('example.clerk.accounts.dev$')}`;

afterEach(() => {
  vi.restoreAllMocks();
  resetFakeAuthWarning();
});

describe('fake auth', () => {
  it('is active only with fixtures data and TI_ENV=local', () => {
    expect(fakeAuthActive({ AUTH_MODE: 'fake', DATA_SOURCE: 'fixtures', TI_ENV: 'local' })).toBe(true);
    // No DATA_SOURCE and no binding falls back to fixtures.
    expect(fakeAuthActive({ AUTH_MODE: 'fake', TI_ENV: 'local' })).toBe(true);
  });

  it('is ignored (and logged once) in api mode, in staging and in production', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(fakeAuthActive({ AUTH_MODE: 'fake', DATA_SOURCE: 'api', API: api, TI_ENV: 'local' })).toBe(false);
    expect(fakeAuthActive({ AUTH_MODE: 'fake', DATA_SOURCE: 'fixtures', TI_ENV: 'staging' })).toBe(false);
    expect(fakeAuthActive({ AUTH_MODE: 'fake', DATA_SOURCE: 'fixtures', TI_ENV: 'production' })).toBe(false);
    expect(fakeAuthActive({ AUTH_MODE: 'fake', DATA_SOURCE: 'fixtures' })).toBe(false);
    expect(log).toHaveBeenCalledTimes(1);
  });

  it('is off without AUTH_MODE=fake, and says nothing', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(fakeAuthActive({ DATA_SOURCE: 'fixtures', TI_ENV: 'local' })).toBe(false);
    expect(fakeAuthActive({ AUTH_MODE: 'real', DATA_SOURCE: 'fixtures', TI_ENV: 'local' })).toBe(false);
    expect(log).not.toHaveBeenCalled();
  });

  it('picks the auth mode: fake, else Clerk when configured, else off', () => {
    const base = { CLERK_PUBLISHABLE_KEY: KEY, CLERK_SECRET_KEY: 'sk_test_x' };
    expect(authMode({ ...base, AUTH_MODE: 'fake', DATA_SOURCE: 'fixtures', TI_ENV: 'local' }).kind).toBe(
      'fake',
    );
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(authMode({ ...base, AUTH_MODE: 'fake', TI_ENV: 'production' }).kind).toBe('clerk');
    expect(authMode({ TI_ENV: 'production' }).kind).toBe('off');
    expect(authMode({ CLERK_PUBLISHABLE_KEY: KEY }).kind).toBe('off');
  });

  it('reads only a well-formed fake cookie', () => {
    const get = (cookie: string) =>
      readFakeUser(new Request('https://x.test/', { headers: { Cookie: cookie } }));
    expect(get(`a=1; ${FAKE_COOKIE}=bob7; b=2`)).toBe('bob7');
    expect(get(`${FAKE_COOKIE}=Bob`)).toBeNull();
    expect(get(`${FAKE_COOKIE}=${'a'.repeat(21)}`)).toBeNull();
    expect(get(`${FAKE_COOKIE}=`)).toBeNull();
    expect(get('other=1')).toBeNull();
    expect(readFakeUser(new Request('https://x.test/'))).toBeNull();
  });

  it('sets an HttpOnly, SameSite=Lax cookie and clears it', () => {
    expect(fakeSignInCookie('bob')).toBe(`${FAKE_COOKIE}=bob; Path=/; HttpOnly; SameSite=Lax`);
    expect(fakeSignOutCookie()).toContain('Max-Age=0');
    expect(fakeSignOutCookie()).toContain('HttpOnly');
  });
});

describe('localPath', () => {
  it('keeps same-site paths and sends everything else home', () => {
    expect(localPath('/e/CVE-1?tab=evidence')).toBe('/e/CVE-1?tab=evidence');
    for (const bad of [
      null,
      '',
      'https://evil.test/',
      '//evil.test',
      '/\\evil.test',
      'e/x',
      '/a\nb',
      `/${'a'.repeat(600)}`,
    ])
      expect(localPath(bad)).toBe('/');
  });
});
