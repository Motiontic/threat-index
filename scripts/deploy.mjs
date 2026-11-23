// Deploys every Worker to one environment: fills the configs, applies pending D1 migrations,
// deploys queue consumers before producers, then checks the API's health endpoint.
// CI runs this (.github/workflows/deploy.yml); staging on every green push to main,
// production only after a person approves the `production` environment.
//
//   node scripts/deploy.mjs <staging|production>
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { APPS, loadDotEnv, ROOT, TARGETS, writeDeployConfig } from './wrangler-config.mjs';

export const DATABASES = ['ti_control', 'ti_vulns', 'ti_advisories', 'ti_signals', 'ti_world', 'ti_users'];
const DEPLOY_ORDER = ['loader', 'notify', 'api', 'collector'];

export function wrangler(args) {
  return execFileSync(join(ROOT, 'node_modules', '.bin', 'wrangler'), args, {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, CI: process.env.CI ?? '1' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
}

export function envArgs(target) {
  return target === 'staging' ? ['--env', 'staging'] : [];
}

/** Applies every pending migration for the six databases of one environment. */
export function migrate(target, apiConfig) {
  const suffix = target === 'staging' ? '_staging' : '';
  for (const db of DATABASES) {
    process.stdout.write(
      wrangler(['d1', 'migrations', 'apply', db + suffix, '--remote', ...envArgs(target), '-c', apiConfig]),
    );
  }
}

export async function checkHealth(baseUrl) {
  const url = `${baseUrl.replace(/\/$/, '')}/v1/health`;
  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      const res = await fetch(url);
      if (res.ok && (await res.json()).ok === true) {
        console.log(`✓ ${url} is healthy`);
        return;
      }
      console.log(`… ${url} returned ${res.status} (attempt ${attempt})`);
    } catch (err) {
      console.log(`… ${url} unreachable: ${err.message} (attempt ${attempt})`);
    }
    await new Promise((r) => setTimeout(r, 3000 * attempt));
  }
  throw new Error(`${url} did not become healthy`);
}

async function main() {
  const target = process.argv[2];
  if (!TARGETS.includes(target)) {
    console.error('usage: node scripts/deploy.mjs <staging|production>');
    process.exit(2);
  }
  loadDotEnv();
  const configs = Object.fromEntries(APPS.map((app) => [app, writeDeployConfig(app, target)]));

  console.log(`\n▸ D1 migrations (${target})`);
  migrate(target, configs.api);

  let apiUrl;
  for (const app of DEPLOY_ORDER.filter((a) => configs[a])) {
    console.log(`\n▸ deploy ${app} (${target})`);
    const out = wrangler(['deploy', ...envArgs(target), '-c', configs[app]]);
    process.stdout.write(out);
    if (app === 'api') apiUrl = out.match(/https:\/\/[^\s]+\.workers\.dev/)?.[0];
  }

  const base = apiUrl ?? (target === 'staging' ? process.env.TI_API_URL_STAGING : process.env.TI_API_URL);
  if (!base) throw new Error('could not find the API URL; set TI_API_URL_STAGING / TI_API_URL');
  await checkHealth(base);
}

if (process.argv[1]?.endsWith('deploy.mjs')) {
  main().catch((err) => {
    console.error(err.message ?? err);
    process.exit(1);
  });
}
