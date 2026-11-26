// Deploys every Worker to one environment: fills the configs, applies pending D1 migrations,
// deploys queue consumers before producers, then checks the API's health endpoint.
// CI runs this (.github/workflows/deploy.yml); staging on every green push to main,
// production only after a person approves the `production` environment.
//
// Production refuses to run unless the working tree is clean, HEAD is on origin/main and nothing is unpushed
// (`productionGuard`). There is no flag to skip it.
//
//   node scripts/deploy.mjs <staging|production>
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { buildWeb, builtWebConfig, checkWeb, webDeployArgs } from '../apps/web/scripts/deploy-web.mjs';
import { APPS, loadDotEnv, ROOT, TARGETS, writeDeployConfig } from './wrangler-config.mjs';

export const DATABASES = ['ti_control', 'ti_vulns', 'ti_advisories', 'ti_signals', 'ti_world', 'ti_users'];
// ti-api before mcp (its service binding), mcp before web (web's MCP binding), web last. An app missing from
// this list is never deployed.
export const DEPLOY_ORDER = ['loader', 'notify', 'api', 'collector', 'mcp', 'web'];

/** Runs git in `cwd` and returns { ok, out }: ok is false on a non-zero exit. */
function git(args, cwd = ROOT) {
  try {
    return { ok: true, out: execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim() };
  } catch (err) {
    return { ok: false, out: String(err.stdout ?? '').trim() };
  }
}

/**
 * Why production must not be deployed from this checkout, as a list of sentences (empty: go ahead).
 * It must have a clean working tree (untracked files count), HEAD must be on origin/main, and every commit
 * must already be on a remote. A tag deploy in CI passes when the tagged commit is on main.
 */
export function productionGuard(cwd = ROOT, run = git) {
  const problems = [];
  const status = run(['status', '--porcelain'], cwd);
  if (!status.ok) return ['could not read the git state of this checkout (is it a git repository?)'];
  if (status.out !== '') problems.push('the working tree is not clean: commit, stash or remove your changes first');
  if (!run(['rev-parse', '--verify', '--quiet', 'origin/main'], cwd).ok) {
    problems.push('origin/main is not known here: run `git fetch origin main` (CI: check out with fetch-depth 0)');
  } else if (!run(['merge-base', '--is-ancestor', 'HEAD', 'origin/main'], cwd).ok) {
    problems.push('HEAD is not on origin/main: production deploys only what is merged to main');
  }
  const unpushed = run(['rev-list', 'HEAD', '--not', '--remotes'], cwd);
  if (!unpushed.ok) problems.push('could not check for unpushed commits');
  else if (unpushed.out !== '') problems.push(`${unpushed.out.split('\n').length} commit(s) on HEAD are not pushed to any remote`);
  return problems;
}

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
  if (target === 'production') {
    const problems = productionGuard();
    if (problems.length > 0) {
      console.error('Refusing to deploy production:');
      for (const p of problems) console.error(`  - ${p}`);
      console.error('Nothing was deployed. Production deploys from a v* tag or the deploy workflow, after approval.');
      process.exit(1);
    }
  }
  loadDotEnv();
  // web has no ${VAR} placeholders and is deployed from its build output, so it has no generated config.
  const configs = Object.fromEntries(
    APPS.filter((app) => app !== 'web').map((app) => [app, writeDeployConfig(app, target)]),
  );

  console.log(`\n▸ D1 migrations (${target})`);
  migrate(target, configs.api);

  let apiUrl;
  let webUrl;
  for (const app of DEPLOY_ORDER.filter((a) => (a === 'web' ? APPS.includes('web') : configs[a]))) {
    console.log(`\n▸ deploy ${app} (${target})`);
    if (app === 'web') {
      // The environment is fixed at build time; never pass --env for this app.
      buildWeb(target);
      // Refuses a missing/pk_test production Clerk key or an AUTH_MODE build, and supplies the key as a var.
      const builtConfig = builtWebConfig(target);
      const out = wrangler(['deploy', '-c', builtConfig, ...webDeployArgs(target, builtConfig)]);
      process.stdout.write(out);
      webUrl = out.match(/https:\/\/[^\s]+\.workers\.dev/)?.[0];
      continue;
    }
    const out = wrangler(['deploy', ...envArgs(target), '-c', configs[app]]);
    process.stdout.write(out);
    if (app === 'api') apiUrl = out.match(/https:\/\/[^\s]+\.workers\.dev/)?.[0];
  }

  const base = apiUrl ?? (target === 'staging' ? process.env.TI_API_URL_STAGING : process.env.TI_API_URL);
  if (!base) throw new Error('could not find the API URL; set TI_API_URL_STAGING / TI_API_URL');
  await checkHealth(base);

  if (APPS.includes('web')) {
    const site = webUrl ?? (target === 'staging' ? process.env.TI_APP_URL_STAGING : process.env.TI_APP_URL);
    if (!site) throw new Error('could not find the web URL; set TI_APP_URL_STAGING / TI_APP_URL');
    await checkWeb(site);
  }
}

if (process.argv[1]?.endsWith('deploy.mjs')) {
  main().catch((err) => {
    console.error(err.message ?? err);
    process.exit(1);
  });
}
