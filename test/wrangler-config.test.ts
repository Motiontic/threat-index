// biome-ignore-all lint/suspicious/noTemplateCurlyInString: the tests are about ${VAR} placeholders
import { expect, it } from 'vitest';
// @ts-expect-error plain .mjs script without types
import { fillConfig } from '../scripts/wrangler-config.mjs';

const config = {
  name: 'app',
  kv: [{ binding: 'KV', id: '${KV_ID}' }],
  send_email: [{ name: 'OPS_EMAIL', destination_address: '${OPS?}' }],
  vars: { UA: 'x (${OPS?})', FROM: '${FROM?}', PLAIN: 'p' },
  env: {
    staging: {
      kv: [{ binding: 'KV', id: '${KV_ID_STAGING}' }],
      send_email: [{ name: 'S', destination_address: '${OPS?}' }],
      vars: { URL: '${URL_STAGING}' },
    },
  },
};
const quiet = () => {};

it('an unset required value throws and names it', () => {
  expect(() => fillConfig(config, 'production', {}, quiet)).toThrow(/KV_ID/);
  expect(() => fillConfig(config, 'staging', { KV_ID_STAGING: 'k' }, quiet)).toThrow(/URL_STAGING/);
});

it('unset optional values drop the binding element and the vars keys', () => {
  const logged: string[] = [];
  const out = fillConfig(config, 'production', { KV_ID: 'k1' }, (m: string) => logged.push(m));
  expect(out.kv).toEqual([{ binding: 'KV', id: 'k1' }]);
  expect('send_email' in out).toBe(false);
  expect(out.vars).toEqual({ PLAIN: 'p' });
  expect(logged.join('\n')).toMatch(/OPS/);
  expect(logged.join('\n')).toMatch(/FROM/);
});

it('set values fill in', () => {
  const out = fillConfig(config, 'production', { KV_ID: 'k1', OPS: 'ops@example.com', FROM: 'a@b.c' }, quiet);
  expect(out.send_email).toEqual([{ name: 'OPS_EMAIL', destination_address: 'ops@example.com' }]);
  expect(out.vars).toEqual({ UA: 'x (ops@example.com)', FROM: 'a@b.c', PLAIN: 'p' });
});

it('the other section is left alone', () => {
  const prod = fillConfig(config, 'production', { KV_ID: 'k1', OPS: 'o@x.y' }, quiet);
  expect(prod.env).toEqual(config.env);
  const stg = fillConfig(config, 'staging', { KV_ID_STAGING: 'k2', URL_STAGING: 'u' }, quiet);
  expect(stg.kv).toEqual(config.kv); // top level untouched, placeholders kept
  expect(stg.env.staging.kv).toEqual([{ binding: 'KV', id: 'k2' }]);
  expect(stg.env.staging.send_email).toBeUndefined();
  expect(stg.env.staging.vars).toEqual({ URL: 'u' });
});

it("ti-mcp's config fills a placeholder inside a longer string (the staging resource URL)", async () => {
  const { readFileSync } = await import('node:fs');
  const ts = (await import('typescript')).default;
  const file = new URL('../apps/mcp/wrangler.jsonc', import.meta.url);
  const parsed = ts.parseConfigFileTextToJson('wrangler.jsonc', readFileSync(file, 'utf8'));
  const vars = {
    TI_SETTINGS_KV_ID_STAGING: 'kv-staging',
    TI_APP_URL_STAGING: 'https://staging.example.test',
    TI_CLERK_ISSUER_STAGING: 'https://clerk.example.test',
  };
  const staging = fillConfig(parsed.config, 'staging', vars, quiet).env.staging;
  expect(staging.vars.MCP_RESOURCE_URL).toBe('https://staging.example.test/mcp');
  expect(staging.vars.CLERK_ISSUER).toBe('https://clerk.example.test');
  const prod = fillConfig(parsed.config, 'production', { TI_SETTINGS_KV_ID: 'kv', TI_CLERK_ISSUER: 'https://c.test' }, quiet);
  expect(prod.vars.MCP_RESOURCE_URL).toBe('https://mti.motiontic.com/mcp');
  expect(prod.workers_dev).toBe(false);
  expect(prod.routes).toBeUndefined();
});
