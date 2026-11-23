// @ts-nocheck: uses node:fs, node:os and node:path, which this app's tsconfig has no types for.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { builtWebConfig, webDeployArgs } from '../scripts/deploy-web.mjs';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ti-web-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function build(config: unknown, { redirect = true } = {}) {
  mkdirSync(join(dir, 'build', 'server'), { recursive: true });
  writeFileSync(join(dir, 'build', 'server', 'wrangler.json'), JSON.stringify(config));
  if (redirect) {
    mkdirSync(join(dir, '.wrangler', 'deploy'), { recursive: true });
    writeFileSync(
      join(dir, '.wrangler', 'deploy', 'config.json'),
      JSON.stringify({ configPath: '../../build/server/wrangler.json', auxiliaryWorkers: [] }),
    );
  }
}
const prod = {
  name: 'ti-web',
  vars: { DATA_SOURCE: 'api' },
  services: [{ binding: 'API', service: 'ti-api' }],
};
const staging = {
  name: 'ti-web-staging',
  vars: { DATA_SOURCE: 'api' },
  services: [{ binding: 'API', service: 'ti-api-staging' }],
};

describe('builtWebConfig', () => {
  it('follows the redirect and returns the built config for a matching build', () => {
    build(prod);
    expect(builtWebConfig('production', dir)).toBe(join(dir, 'build', 'server', 'wrangler.json'));
    build(staging);
    expect(builtWebConfig('staging', dir)).toBe(join(dir, 'build', 'server', 'wrangler.json'));
  });

  it('throws when the built worker has the wrong name', () => {
    build(prod);
    expect(() => builtWebConfig('staging', dir)).toThrow(/"ti-web" but staging needs "ti-web-staging"/);
    build(staging);
    expect(() => builtWebConfig('production', dir)).toThrow(/"ti-web-staging" but production needs "ti-web"/);
  });

  it('throws when the API binding targets the wrong worker', () => {
    build({ ...prod, services: [{ binding: 'API', service: 'ti-api-staging' }] });
    expect(() => builtWebConfig('production', dir)).toThrow(/API binding targets "ti-api-staging"/);
    build({ ...staging, services: [{ binding: 'API', service: 'ti-api' }] });
    expect(() => builtWebConfig('staging', dir)).toThrow(/API binding targets "ti-api"/);
    build({ ...prod, services: [] });
    expect(() => builtWebConfig('production', dir)).toThrow(/API binding/);
  });

  it('throws when DATA_SOURCE is not "api"', () => {
    for (const vars of [{ DATA_SOURCE: 'fixtures' }, {}, undefined]) {
      build({ ...prod, vars });
      expect(() => builtWebConfig('production', dir)).toThrow(/DATA_SOURCE is .* needs "api"/);
      build({ ...staging, vars });
      expect(() => builtWebConfig('staging', dir)).toThrow(/needs "api"/);
    }
  });

  it('throws when there is no redirect file', () => {
    build(prod, { redirect: false });
    expect(() => builtWebConfig('production', dir)).toThrow(/no build found/);
  });

  it('throws for an unknown target', () => {
    expect(() => builtWebConfig('preview', dir)).toThrow(/unknown target/);
  });
});

describe('webDeployArgs', () => {
  const TEST = `pk_test_${btoa('example.clerk.accounts.dev$')}`;
  const LIVE = `pk_live_${btoa('clerk.example.com$')}`;
  const path = () => join(dir, 'build', 'server', 'wrangler.json');

  it('passes the staging key as a --var, read from the staging variable only', () => {
    build(staging);
    expect(webDeployArgs('staging', path(), { TI_CLERK_PUBLISHABLE_KEY_STAGING: TEST })).toEqual([
      '--var',
      `CLERK_PUBLISHABLE_KEY:${TEST}`,
    ]);
    expect(() => webDeployArgs('staging', path(), { TI_CLERK_PUBLISHABLE_KEY: TEST })).toThrow(
      /TI_CLERK_PUBLISHABLE_KEY_STAGING is not set/,
    );
  });

  it('passes the production key from TI_CLERK_PUBLISHABLE_KEY', () => {
    build(prod);
    expect(webDeployArgs('production', path(), { TI_CLERK_PUBLISHABLE_KEY: LIVE })).toEqual([
      '--var',
      `CLERK_PUBLISHABLE_KEY:${LIVE}`,
    ]);
  });

  it('refuses a missing or empty key, and a value that is not a publishable key', () => {
    build(staging);
    expect(() => webDeployArgs('staging', path(), {})).toThrow(/not set/);
    expect(() => webDeployArgs('staging', path(), { TI_CLERK_PUBLISHABLE_KEY_STAGING: '  ' })).toThrow(
      /not set/,
    );
    expect(() =>
      webDeployArgs('staging', path(), { TI_CLERK_PUBLISHABLE_KEY_STAGING: 'sk_test_secret' }),
    ).toThrow(/not a Clerk publishable key/);
  });

  it('refuses a pk_test_ key for production', () => {
    build(prod);
    expect(() => webDeployArgs('production', path(), { TI_CLERK_PUBLISHABLE_KEY: TEST })).toThrow(/pk_live_/);
  });

  it('refuses a build whose config has an AUTH_MODE var, for any value', () => {
    for (const value of ['fake', 'real', '']) {
      build({ ...staging, vars: { DATA_SOURCE: 'api', AUTH_MODE: value } });
      expect(() => webDeployArgs('staging', path(), { TI_CLERK_PUBLISHABLE_KEY_STAGING: TEST })).toThrow(
        /AUTH_MODE/,
      );
    }
  });
});
