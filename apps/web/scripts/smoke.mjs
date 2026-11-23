// Smoke check of the BUILT app in workerd: starts `wrangler dev` on the built config, requests every
// public route, and exits 1 listing each failure. Always stops wrangler.
//
//   node scripts/smoke.mjs        (after `react-router build`; PORT defaults to 8710)
import { spawn } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { builtWebConfig, WEB_DIR } from './deploy-web.mjs';

// Built from pieces so a repo-wide search for the forbidden markup finds only real uses.
const FORBIDDEN_FORM_ATTRS = new RegExp(
  ['type="pass' + 'word"', '-pass' + 'word"', 'method="po' + 'st"'].join('|'),
  'i',
);

const PORT = Number(process.env.PORT ?? 8710);
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT = resolve(WEB_DIR, '..', '..');
const NVD = 'This product uses the NVD API but is not endorsed or certified by the NVD.';
const failures = [];
const fail = (where, what) => failures.push(`${where}: ${what}`);

const PAGES = [
  ['/', 'Every vulnerability'],
  ['/search', 'Everything'],
  ['/search?q=log4j', 'Results for “log4j”'],
  ['/search?type=vuln&sig=kev', 'Vulnerabilities'],
  ['/e/CVE-2025-3248', 'CVE-2025-3248: Langflow unauthenticated code execution'],
  ['/index', 'Index A–Z'],
  ['/index/l', 'Index: L'],
  ['/sources', 'Sources'],
  ['/sources?status=on', 'Sources'],
  ['/account', 'Account'],
];

const count = (html, re) => (html.match(re) ?? []).length;

function checkDocument(path, res, html, { title, status = 200 }) {
  if (res.status !== status) fail(path, `status ${res.status}, wanted ${status}`);
  if (!(res.headers.get('content-type') ?? '').includes('text/html')) fail(path, 'not HTML');
  const t = html.match(/<title[^>]*>([^<]*)<\/title>/)?.[1];
  if (!t) fail(path, 'no <title>');
  else if (!t.includes(title.replace(/&/g, '&amp;'))) fail(path, `title "${t}" lacks "${title}"`);
  if (count(html, /<h1[\s>]/g) !== 1) fail(path, `${count(html, /<h1[\s>]/g)} <h1> elements`);
  for (const tag of ['header', 'nav', 'main', 'footer']) {
    if (!new RegExp(`<${tag}[\\s>]`).test(html)) fail(path, `no <${tag}>`);
  }
  if (!html.includes(NVD)) fail(path, 'NVD notice missing');
  if (res.headers.get('x-robots-tag') !== 'noindex') fail(path, 'X-Robots-Tag is not noindex');
  const csp = res.headers.get('content-security-policy') ?? '';
  const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
  if (!nonce) fail(path, 'no CSP nonce');
  const scripts = html.match(/<script\b[^>]*>/g) ?? [];
  for (const s of scripts) {
    if (!nonce || !s.includes(`nonce="${nonce}"`))
      fail(path, `script without the CSP nonce: ${s.slice(0, 80)}`);
  }
  if (FORBIDDEN_FORM_ATTRS.test(html)) fail(path, 'password field or POST form');
  if (/\sstyle="/.test(html)) fail(path, 'style attribute (blocked by the CSP)');
}

async function get(path, init) {
  const res = await fetch(BASE + path, { redirect: 'manual', ...init });
  return { res, html: await res.text() };
}

async function runChecks() {
  let stylesheet;
  for (const [path, title] of PAGES) {
    const { res, html } = await get(path);
    checkDocument(path, res, html, { title });
    if (path === '/') stylesheet = html.match(/<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"/)?.[1];
  }

  {
    const path = '/e/CVE-2025-3248';
    const { html } = await get(path);
    const fixture = JSON.parse(readFileSync(join(WEB_DIR, 'app/data/fixtures/entries.json'), 'utf8')).find(
      (e) => e.key === 'CVE-2025-3248',
    );
    if (!html.includes(fixture.summary)) fail(path, 'summary not in the server HTML');
    if (!html.includes('9.8')) fail(path, 'CVSS 9.8 missing');
    if (!html.includes('Exploited in the wild')) fail(path, '"Exploited in the wild" missing');
    if (!html.includes('application/ld+json')) fail(path, 'JSON-LD missing');
  }

  for (const from of ['/e/cve-2025-3248', '/e/GHSA-c995-4fw3-j39m']) {
    const { res } = await get(from);
    const loc = res.headers.get('location') ?? '';
    if (res.status !== 301) fail(from, `status ${res.status}, wanted 301`);
    if (!loc.endsWith('/e/CVE-2025-3248')) fail(from, `redirects to "${loc}"`);
    if (!res.headers.get('content-security-policy')?.includes("'nonce-")) fail(from, 'redirect has no CSP');
    if (res.headers.get('x-robots-tag') !== 'noindex') fail(from, 'redirect has no X-Robots-Tag: noindex');
    if (res.headers.get('x-content-type-options') !== 'nosniff') fail(from, 'redirect has no nosniff');
  }

  for (const path of ['/e/CVE-1999-99999', '/no-such-page', '/index/ab']) {
    const { res, html } = await get(path);
    checkDocument(path, res, html, { title: 'Not found', status: 404 });
  }

  if (!stylesheet) fail('/', 'no stylesheet link');
  else {
    const res = await fetch(BASE + stylesheet);
    await res.arrayBuffer();
    if (res.status !== 200) fail(stylesheet, `status ${res.status}`);
    const cc = res.headers.get('cache-control') ?? '';
    if (!cc.includes('public, max-age=31536000, immutable')) fail(stylesheet, `Cache-Control "${cc}"`);
  }

  // No fixture text may ship to the browser.
  const summaries = JSON.parse(readFileSync(join(WEB_DIR, 'app/data/fixtures/entries.json'), 'utf8')).map(
    (e) => e.summary,
  );
  const walk = (dir) =>
    readdirSync(dir).flatMap((f) => {
      const p = join(dir, f);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });
  for (const file of walk(join(WEB_DIR, 'build/client'))) {
    if (/\.(woff2?|png|ico)$/.test(file)) continue;
    const text = readFileSync(file, 'utf8');
    for (const s of summaries) {
      if (text.includes(s.slice(0, 60))) fail(file, 'contains fixture text');
    }
  }
}

async function waitUntilUp(child) {
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error(`wrangler dev exited early (code ${child.exitCode})`);
    try {
      const res = await fetch(`${BASE}/`);
      await res.arrayBuffer();
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error('wrangler dev did not start in 60 s');
}

function stop(child) {
  if (child.exitCode !== null || !child.pid) return;
  try {
    process.kill(-child.pid, 'SIGTERM');
  } catch {
    child.kill('SIGTERM');
  }
}

async function main() {
  const config = builtWebConfig('production');
  const child = spawn(
    join(ROOT, 'node_modules', '.bin', 'wrangler'),
    ['dev', '-c', config, '--ip', '127.0.0.1', '--port', String(PORT)],
    {
      cwd: ROOT,
      detached: true,
      stdio: ['ignore', 'inherit', 'inherit'],
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1' },
    },
  );
  const onSignal = () => {
    stop(child);
    process.exit(130);
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  try {
    await waitUntilUp(child);
    await runChecks();
  } catch (err) {
    fail('smoke', err.message ?? String(err));
  } finally {
    stop(child);
  }
  if (failures.length > 0) {
    console.error(`\n${failures.length} smoke failure(s):`);
    for (const f of failures) console.error(`  ✗ ${f}`);
    process.exit(1);
  }
  console.log(`✓ smoke: ${PAGES.length + 6} routes and the build checks passed`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
