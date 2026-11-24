import { describe, expect, it } from 'vitest';
import { clerkConfig, decodePublishableKey } from '../app/lib/clerk-config.server';

const b64 = (host: string) => btoa(`${host}$`);
const TEST_KEY = `pk_test_${b64('example.clerk.accounts.dev')}`;
const LIVE_KEY = `pk_live_${b64('clerk.example.com')}`;
const SECRET = 'sk_test_dummydummydummy';

describe('clerkConfig', () => {
  it('decodes a test key and a live key to their frontend host', () => {
    expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: TEST_KEY, CLERK_SECRET_KEY: SECRET })).toEqual({
      publishableKey: TEST_KEY,
      frontendApi: 'example.clerk.accounts.dev',
    });
    expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: LIVE_KEY, CLERK_SECRET_KEY: 'sk_live_abc' })).toEqual({
      publishableKey: LIVE_KEY,
      frontendApi: 'clerk.example.com',
    });
  });

  it('decodes the production key for clerk.mti.motiontic.com', () => {
    const key = `pk_live_${b64('clerk.mti.motiontic.com')}`;
    expect(decodePublishableKey(key)).toEqual({ frontendApi: 'clerk.mti.motiontic.com', live: true });
    expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: key, CLERK_SECRET_KEY: 'sk_live_abc' })).toEqual({
      publishableKey: key,
      frontendApi: 'clerk.mti.motiontic.com',
    });
  });

  it('is null (Clerk off) without a secret, without a key, or with a bad secret', () => {
    expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: TEST_KEY })).toBeNull();
    expect(clerkConfig({ CLERK_SECRET_KEY: SECRET })).toBeNull();
    expect(clerkConfig({})).toBeNull();
    expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: TEST_KEY, CLERK_SECRET_KEY: 'whatever' })).toBeNull();
    expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: TEST_KEY, CLERK_SECRET_KEY: '' })).toBeNull();
  });

  it('is null for a malformed key', () => {
    for (const bad of [
      'pk_test_',
      'pk_dev_abc',
      'nonsense',
      `pk_test_${btoa('example.clerk.accounts.dev')}`, // no trailing $
      `pk_test_${b64('evil.example.com')}`, // test key on a host that is not a Clerk dev domain
      `pk_live_${b64('example.com')}`, // live key without the clerk. prefix
      `pk_test_${b64('exa mple.clerk.accounts.dev')}`,
      `pk_test_${b64('Example.clerk.accounts.dev')}`, // upper case is not in the host pattern
      `pk_test_${b64('a.com/x.clerk.accounts.dev')}`,
      `pk_test_${b64('x.clerk.accounts.dev:8080')}`,
      `pk_test_${b64('a@b.clerk.accounts.dev')}`,
    ]) {
      expect(clerkConfig({ CLERK_PUBLISHABLE_KEY: bad, CLERK_SECRET_KEY: SECRET }), bad).toBeNull();
    }
  });

  it('does not treat a live host on a test key (or the reverse) as valid', () => {
    expect(decodePublishableKey(`pk_test_${b64('clerk.example.com')}`)).toBeNull();
    expect(decodePublishableKey(`pk_live_${b64('example.clerk.accounts.dev')}`)).toBeNull();
  });
});
