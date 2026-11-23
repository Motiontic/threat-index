import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import apiText from '../../api/wrangler.jsonc?raw';
import webText from '../wrangler.jsonc?raw';

interface Service {
  binding: string;
  service: string;
}
interface WranglerConfig {
  name: string;
  main: string;
  compatibility_date: string;
  compatibility_flags: string[];
  observability: unknown;
  vars: unknown;
  services: Service[];
  env: { staging: { name: string; vars: unknown; services: Service[] } };
}

// `ts` is what scripts/wrangler-config.mjs uses to read these files too.
function parse(text: string): WranglerConfig {
  const { config, error } = ts.parseConfigFileTextToJson('wrangler.jsonc', text);
  if (error) throw new Error(String(error.messageText));
  return config as WranglerConfig;
}
const web = parse(webText);
const api = parse(apiText);

describe('apps/web/wrangler.jsonc', () => {
  it('is the production worker at the top level', () => {
    expect(web.name).toBe('ti-web');
    expect(web.main).toBe('./workers/app.ts');
    expect(web.compatibility_flags).toContain('nodejs_compat');
    expect(web.observability).toEqual({ enabled: true });
    expect(web.vars).toEqual({ TI_ENV: 'production' });
    expect(web.services).toEqual([{ binding: 'API', service: 'ti-api' }]);
  });

  it('is the staging worker under env.staging', () => {
    expect(web.env.staging.name).toBe('ti-web-staging');
    expect(web.env.staging.vars).toEqual({ TI_ENV: 'staging' });
    expect(web.env.staging.services).toEqual([{ binding: 'API', service: 'ti-api-staging' }]);
  });

  it('targets the same API workers that apps/api deploys', () => {
    expect(web.services[0]?.service).toBe(api.name);
    expect(web.env.staging.services[0]?.service).toBe(`${api.name}-staging`);
  });

  it('uses the same compatibility date as the api', () => {
    expect(web.compatibility_date).toBe(api.compatibility_date);
    expect(web.compatibility_date).toBe('2026-11-01');
  });

  it('has no variable placeholders, so wrangler-config.mjs has nothing to fill', () => {
    expect(webText).not.toContain(['$', '{'].join(''));
  });

  it('explains that the environment is chosen at build time', () => {
    expect(webText).toMatch(/BUILD TIME/);
    expect(webText).toContain('CLOUDFLARE_ENV=staging');
    expect(webText).toContain('build/server/wrangler.json');
    expect(webText).toContain('.wrangler/deploy/config.json');
  });
});
