// @ts-nocheck: uses node:fs, node:os and node:path, which this app's tsconfig has no types for.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { builtWebConfig } from '../scripts/deploy-web.mjs';

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
const prod = { name: 'ti-web', services: [{ binding: 'API', service: 'ti-api' }] };
const staging = { name: 'ti-web-staging', services: [{ binding: 'API', service: 'ti-api-staging' }] };

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
    build({ name: 'ti-web', services: [{ binding: 'API', service: 'ti-api-staging' }] });
    expect(() => builtWebConfig('production', dir)).toThrow(/API binding targets "ti-api-staging"/);
    build({ name: 'ti-web-staging', services: [{ binding: 'API', service: 'ti-api' }] });
    expect(() => builtWebConfig('staging', dir)).toThrow(/API binding targets "ti-api"/);
    build({ name: 'ti-web', services: [] });
    expect(() => builtWebConfig('production', dir)).toThrow(/API binding/);
  });

  it('throws when there is no redirect file', () => {
    build(prod, { redirect: false });
    expect(() => builtWebConfig('production', dir)).toThrow(/no build found/);
  });

  it('throws for an unknown target', () => {
    expect(() => builtWebConfig('preview', dir)).toThrow(/unknown target/);
  });
});
