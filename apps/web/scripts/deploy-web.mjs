// Deploy helpers for ti-web. The environment is chosen when the app is BUILT (CLOUDFLARE_ENV), not by
// `wrangler deploy --env`, so before deploying we read the built config back and refuse a stale or
// wrong-environment build.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDotEnv } from '../../../scripts/wrangler-config.mjs';

export const WEB_DIR = fileURLToPath(new URL('..', import.meta.url));
const ROOT = resolve(WEB_DIR, '..', '..');

const EXPECTED = {
  staging: { name: 'ti-web-staging', api: 'ti-api-staging' },
  production: { name: 'ti-web', api: 'ti-api' },
};

/** Runs `react-router build` for one environment and returns when it has finished. */
export function buildWeb(target) {
  if (!EXPECTED[target]) throw new Error(`unknown target "${target}"`);
  const env = { ...process.env };
  if (target === 'staging') env.CLOUDFLARE_ENV = 'staging';
  else delete env.CLOUDFLARE_ENV;
  execFileSync('pnpm', ['--filter', '@ti/web', 'build'], { cwd: ROOT, env, stdio: 'inherit' });
}

/**
 * Follows .wrangler/deploy/config.json to the built config and checks it belongs to `target`.
 * Returns the built config's path. Throws if the redirect is missing or the build is for another environment.
 */
export function builtWebConfig(target, dir = WEB_DIR) {
  const expected = EXPECTED[target];
  if (!expected) throw new Error(`unknown target "${target}"`);
  const redirect = resolve(dir, '.wrangler', 'deploy', 'config.json');
  if (!existsSync(redirect))
    throw new Error(`no build found: ${redirect} is missing; run buildWeb("${target}") first`);
  const { configPath } = JSON.parse(readFileSync(redirect, 'utf8'));
  if (typeof configPath !== 'string') throw new Error(`${redirect} has no configPath`);
  const built = resolve(dirname(redirect), configPath);
  if (!existsSync(built)) throw new Error(`${redirect} points at ${built}, which does not exist`);
  const config = JSON.parse(readFileSync(built, 'utf8'));
  if (config.name !== expected.name) {
    throw new Error(
      `built worker is "${config.name}" but ${target} needs "${expected.name}"; rebuild for ${target}`,
    );
  }
  const api = (config.services ?? []).find((s) => s.binding === 'API');
  if (api?.service !== expected.api) {
    throw new Error(
      `built API binding targets "${api?.service}" but ${target} needs "${expected.api}"; rebuild for ${target}`,
    );
  }
  if (config.vars?.DATA_SOURCE !== 'api') {
    throw new Error(
      `built DATA_SOURCE is "${config.vars?.DATA_SOURCE}" but ${target} needs "api"; check wrangler.jsonc and rebuild`,
    );
  }
  return built;
}

/**
 * The extra `wrangler deploy` arguments for ti-web: the Clerk publishable key as a plain var, read from
 * TI_CLERK_PUBLISHABLE_KEY_STAGING (staging) or TI_CLERK_PUBLISHABLE_KEY (production), in the environment or the
 * repo's .env, and the /ops admin list from TI_ADMIN_USER_IDS (optional). Refuses to deploy when the key is missing, when production would get a `pk_test_` key, or when the
 * built config has an `AUTH_MODE` var (fake sign-in must never ship). The secret key is a Worker secret, set once
 * with `wrangler secret put CLERK_SECRET_KEY`; it never passes through here.
 */
export function webDeployArgs(target, builtConfigPath, env = process.env) {
  if (!EXPECTED[target]) throw new Error(`unknown target "${target}"`);
  if (env === process.env) loadDotEnv();
  const config = JSON.parse(readFileSync(builtConfigPath, 'utf8'));
  if (config.vars && Object.hasOwn(config.vars, 'AUTH_MODE')) {
    throw new Error('the built config has an AUTH_MODE var; fake sign-in must never be deployed');
  }
  const name = target === 'staging' ? 'TI_CLERK_PUBLISHABLE_KEY_STAGING' : 'TI_CLERK_PUBLISHABLE_KEY';
  const key = (env[name] ?? '').trim();
  if (!key) throw new Error(`${name} is not set; ti-web needs the Clerk publishable key to deploy`);
  if (!/^pk_(test|live)_[A-Za-z0-9+/_=-]+$/.test(key))
    throw new Error(`${name} is not a Clerk publishable key`);
  if (target === 'production' && key.startsWith('pk_test_')) {
    throw new Error('production needs a pk_live_ Clerk key, but TI_CLERK_PUBLISHABLE_KEY is a pk_test_ key');
  }
  const args = ['--var', `CLERK_PUBLISHABLE_KEY:${key}`];
  // The admin list for /ops: user ids, never secrets. Optional: with none, /ops is a 404 for everyone.
  const admins = (env.TI_ADMIN_USER_IDS ?? '').trim();
  if (admins) {
    if (!/^user_[A-Za-z0-9]{1,64}(\s*,\s*user_[A-Za-z0-9]{1,64}){0,19}$/.test(admins))
      throw new Error('TI_ADMIN_USER_IDS must be a comma list of Clerk user ids (user_...)');
    args.push('--var', `ADMIN_USER_IDS:${admins.replace(/\s+/g, '')}`);
  }
  return args;
}

/** Waits (with retries, like checkHealth) until GET / answers 200 with HTML. */
export async function checkWeb(baseUrl) {
  const url = `${baseUrl.replace(/\/$/, '')}/`;
  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      const res = await fetch(url);
      if (res.ok && (res.headers.get('content-type') ?? '').includes('text/html')) {
        console.log(`✓ ${url} is serving HTML`);
        return;
      }
      console.log(`… ${url} returned ${res.status} (attempt ${attempt})`);
    } catch (err) {
      console.log(`… ${url} unreachable: ${err.message} (attempt ${attempt})`);
    }
    await new Promise((r) => setTimeout(r, 3000 * attempt));
  }
  throw new Error(`${url} did not start serving HTML`);
}
