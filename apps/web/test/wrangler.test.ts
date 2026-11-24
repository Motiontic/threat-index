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
  routes?: unknown;
  env: { staging: { name: string; vars: unknown; services: Service[]; routes?: unknown } };
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
    expect(web.vars).toEqual({ TI_ENV: 'production', DATA_SOURCE: 'api' });
    expect(web.services).toEqual([{ binding: 'API', service: 'ti-api' }]);
  });

  it('serves production on mti.motiontic.com, and staging on workers.dev only', () => {
    expect(web.routes).toEqual([{ pattern: 'mti.motiontic.com', custom_domain: true }]);
    expect(web.env.staging.routes ?? []).toEqual([]);
  });

  it('is the staging worker under env.staging', () => {
    expect(web.env.staging.name).toBe('ti-web-staging');
    expect(web.env.staging.vars).toEqual({ TI_ENV: 'staging', DATA_SOURCE: 'api' });
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

describe('rate limit bindings', () => {
  type Rl = { name: string; namespace_id: string; simple: { limit: number; period: number } }[];
  const top = (c: unknown) => (c as { ratelimits: Rl }).ratelimits;
  const staging = (c: unknown) => (c as { env: { staging: { ratelimits: Rl } } }).env.staging.ratelimits;

  it('both apps declare their bindings at the top level and again in env.staging', () => {
    expect(top(api).map((r) => r.name)).toEqual(['RL_PUBLIC', 'RL_USER', 'RL_DEEP']);
    expect(staging(api).map((r) => r.name)).toEqual(['RL_PUBLIC', 'RL_USER', 'RL_DEEP']);
    expect(top(web).map((r) => r.name)).toEqual(['RL_PAGES']);
    expect(staging(web).map((r) => r.name)).toEqual(['RL_PAGES']);
  });

  it('every namespace id is an integer string and none is shared between apps or environments', () => {
    const all = [...top(api), ...staging(api), ...top(web), ...staging(web)];
    const ids = all.map((r) => r.namespace_id);
    for (const id of ids) expect(id).toMatch(/^\d+$/);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(['7101', '7102', '7103', '7201', '7202', '7203', '7104', '7204']);
  });

  it('uses the specified limits and periods', () => {
    const lim = (rl: Rl) => rl.map((r) => [r.name, r.simple.limit, r.simple.period]);
    const apiLimits = [
      ['RL_PUBLIC', 120, 60],
      ['RL_USER', 240, 60],
      ['RL_DEEP', 5, 60],
    ];
    expect(lim(top(api))).toEqual(apiLimits);
    expect(lim(staging(api))).toEqual(apiLimits);
    expect(lim(top(web))).toEqual([['RL_PAGES', 120, 60]]);
    expect(lim(staging(web))).toEqual([['RL_PAGES', 120, 60]]);
  });

  it('puts no admin id in the repo', () => {
    expect(apiText).not.toMatch(/user_[A-Za-z0-9]{6,}/);
    expect(webText).not.toMatch(/user_[A-Za-z0-9]{6,}/);
  });
});
