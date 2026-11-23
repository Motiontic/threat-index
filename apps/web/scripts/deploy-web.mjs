// Deploy helpers for ti-web. The environment is chosen when the app is BUILT (CLOUDFLARE_ENV), not by
// `wrangler deploy --env`, so before deploying we read the built config back and refuse a stale or
// wrong-environment build.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
  return built;
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
