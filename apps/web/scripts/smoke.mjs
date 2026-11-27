// Smoke check of the BUILT app in workerd: starts `wrangler dev` on the built config, requests every
// public route, and exits 1 listing each failure. Always stops wrangler.
//
//   node scripts/smoke.mjs [--mode fixtures|api]   (after `react-router build`; no --mode runs both in turn)
//   fixtures: port 8710, --var DATA_SOURCE:fixtures, band and noindex everywhere.
//   api: port 8711, the web worker bound to scripts/stub-api (fixtureApi plus two test hooks).
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

const modeArg = process.argv.indexOf('--mode');
const MODE = modeArg > -1 ? process.argv[modeArg + 1] : 'both';
if (MODE !== 'fixtures' && MODE !== 'api' && MODE !== 'both') {
  console.error('usage: node scripts/smoke.mjs [--mode fixtures|api]  (no --mode runs both, fixtures first)');
  process.exit(2);
}
const API_MODE = MODE === 'api';
const PORT = Number(process.env.PORT ?? (API_MODE ? 8711 : 8710));
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT = resolve(WEB_DIR, '..', '..');
const BAND = 'Preview with sample data.';
// Dummy Clerk test keys for api mode (no network): the CSP must name this host and nothing wider.
// Fixtures mode runs with Clerk off.
const CLERK_HOST = 'smoke.clerk.accounts.dev';
const CLERK_KEY = `pk_test_${Buffer.from(`${CLERK_HOST}$`).toString('base64')}`;
const CLERK_SECRET = 'sk_test_smokesmokesmokesmoke';
const NVD = 'This product uses the NVD API but is not endorsed or certified by the NVD.';
const failures = [];
const fail = (where, what) => failures.push(`${where}: ${what}`);

// The built config is production: /privacy answers 503 until every [[OWNER: …]] decision is filled in.
const PRIVACY_UNFINISHED = readFileSync(join(WEB_DIR, 'app', 'lib', 'privacy-content.ts'), 'utf8').includes(
  '[[OWNER:',
);

const PAGES = [
  ['/', 'MTI: Motiontic Threat Index'],
  ['/search', 'Everything'],
  ['/search?q=log4j', 'Results for “log4j”'],
  ['/search?type=vuln&sig=kev', 'Vulnerabilities'],
  ['/search?q=log4j&sev=critical&year=2021', 'Results for “log4j”'],
  ['/e/CVE-2025-3248', 'CVE-2025-3248: Langflow unauthenticated code execution'],
  ['/index', 'Index A–Z'],
  ['/index/l', 'Index: L'],
  ['/breaches', 'Breach notices'],
  ['/breach/domain%3Aexample.com%402025-03-04', 'Breach: Example Co.'],
  ['/incidents?kind=ai', 'Incidents'],
  ['/incident/avid/EXAMPLE-AVID-1', 'Invented sample: Example Co. assistant revealed hidden instructions'],
  ['/techniques', 'Techniques and weaknesses'],
  ['/technique/T1195', 'T1195: Supply Chain Compromise'],
  ['/search?type=breach&q=example', 'Results for “example”'],
  ['/sources', 'Sources'],
  ['/sources?status=on', 'Sources'],
  ...(PRIVACY_UNFINISHED ? [] : [['/privacy', 'Privacy']]),
  ['/sign-in', 'Log in'],
  ['/sign-up', 'Sign up'],
];

const count = (html, re) => (html.match(re) ?? []).length;

// Pages that carry a robots meta tag of their own (api mode sends no header for them).
const META_NOINDEX = (path) =>
  path.startsWith('/search') ||
  /^\/(breaches|incidents|techniques)\?/.test(path) ||
  path === '/sign-in' ||
  path === '/sign-up' ||
  path === '/account';

function checkDocument(path, res, html, { title, status = 200 }) {
  if (res.status !== status) fail(path, `status ${res.status}, wanted ${status}`);
  if (!/max-age=\d{7,}/.test(res.headers.get('strict-transport-security') ?? '')) fail(path, 'no HSTS');
  if (!(res.headers.get('content-type') ?? '').includes('text/html')) fail(path, 'not HTML');
  const t = html.match(/<title[^>]*>([^<]*)<\/title>/)?.[1];
  if (!t) fail(path, 'no <title>');
  else if (!t.includes(title.replace(/&/g, '&amp;'))) fail(path, `title "${t}" lacks "${title}"`);
  if (count(html, /<h1[\s>]/g) !== 1) fail(path, `${count(html, /<h1[\s>]/g)} <h1> elements`);
  for (const tag of ['header', 'nav', 'main', 'footer']) {
    if (!new RegExp(`<${tag}[\\s>]`).test(html)) fail(path, `no <${tag}>`);
  }
  if (!html.includes(NVD)) fail(path, 'NVD notice missing');
  const robots = res.headers.get('x-robots-tag');
  const shouldIndex = API_MODE && status < 400;
  if (shouldIndex && robots !== null) fail(path, `X-Robots-Tag is "${robots}", wanted none`);
  if (!shouldIndex && robots !== 'noindex') fail(path, 'X-Robots-Tag is not noindex');
  const metaNoindex = /<meta[^>]*name="robots"[^>]*content="noindex"/.test(html);
  if (API_MODE && status < 400 && META_NOINDEX(path) && !metaNoindex) fail(path, 'no robots noindex meta');
  if (API_MODE && status >= 400 && !metaNoindex) fail(path, 'error page has no robots noindex meta');
  if (API_MODE && html.includes(BAND)) fail(path, 'sample-data band shown in api mode');
  if (!API_MODE && !html.includes(BAND)) fail(path, 'sample-data band missing in fixtures mode');
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

async function checkAccounts() {
  // Signed out, /account sends the visitor to sign in and back.
  {
    const { res } = await get('/account');
    const loc = res.headers.get('location') ?? '';
    if (res.status !== 302) fail('/account', `status ${res.status}, wanted 302 when signed out`);
    if (!loc.endsWith('/sign-in?redirect_url=%2Faccount')) fail('/account', `redirects to "${loc}"`);
    if (!res.headers.get('content-security-policy')?.includes("'nonce-"))
      fail('/account', 'redirect has no CSP');
  }
  // The account action refuses GET, and a POST from another origin, before it does anything.
  {
    const { res } = await get('/account/do');
    if (res.status !== 405) fail('/account/do', `GET status ${res.status}, wanted 405`);
    const post = await get('/account/do', {
      method: 'POST',
      headers: { Origin: 'https://evil.example', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'intent=watch&id=CVE-2025-3248',
    });
    if (post.res.status !== 403)
      fail('/account/do', `foreign-origin POST status ${post.res.status}, wanted 403`);
    const none = await get('/account/do', {
      method: 'POST',
      headers: { Origin: BASE, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'intent=watch&id=CVE-2025-3248',
    });
    if (none.res.status !== 401) fail('/account/do', `signed-out POST status ${none.res.status}, wanted 401`);
  }
  // Fake sign-in does not exist here.
  for (const path of ['/__fake/sign-in?as=bob', '/__fake/sign-out']) {
    const { res } = await get(path);
    if (res.status !== 404) fail(path, `status ${res.status}, wanted 404 outside fake mode`);
  }
  for (const path of ['/sign-in', '/sign-up']) {
    const { res, html } = await get(path);
    const unavailable = html.includes('Sign-in is unavailable');
    if (API_MODE && unavailable) fail(path, 'says sign-in is unavailable although Clerk is configured');
    if (!API_MODE && !unavailable) fail(path, 'does not say sign-in is unavailable with Clerk off');
    if (/<input[^>]*type="password"/i.test(html)) fail(path, 'password input');
    if (!/<meta[^>]*name="robots"[^>]*content="noindex"/.test(html)) fail(path, 'no robots noindex meta');
    const csp = res.headers.get('content-security-policy') ?? '';
    const hosts = [...csp.matchAll(/https:\/\/[^\s;]+/g)].map((m) => m[0]);
    if (csp.includes('*')) fail(path, 'CSP has a wildcard');
    if (API_MODE) {
      const allowed = new Set([
        `https://${CLERK_HOST}`,
        'https://challenges.cloudflare.com',
        'https://cdn.protect.clerk.com',
        'https://img.clerk.com',
      ]);
      for (const h of hosts) if (!allowed.has(h)) fail(path, `CSP names ${h}`);
      const dir = (name) => csp.split('; ').find((d) => d.startsWith(`${name} `)) ?? '';
      for (const name of ['script-src', 'connect-src'])
        if (!dir(name).includes(`https://${CLERK_HOST}`)) fail(path, `${name} lacks the Clerk host`);
      if (!dir('frame-src').includes('https://challenges.cloudflare.com')) fail(path, 'no frame-src');
      if (!dir('frame-ancestors').includes("'none'")) fail(path, 'frame-ancestors changed');
    } else if (hosts.length > 0) {
      fail(path, `CSP names ${hosts.join(', ')} with Clerk off`);
    }
  }
}

// The redesigned shell: a floating bar (no sidebar), a themed first paint from the cookie, the quick-search route.
async function checkShell() {
  const plain = await get('/');
  if (!/<header class="bar"/.test(plain.html)) fail('/', 'no top bar');
  if (/class="rail/.test(plain.html)) fail('/', 'the sidebar is still there');
  if (/<html[^>]*data-theme=/.test(plain.html)) fail('/', 'data-theme set without a stored choice');
  for (const theme of ['dark', 'light']) {
    const { res, html } = await get('/', { headers: { Cookie: `ti-theme=${theme}` } });
    if (!new RegExp(`<html[^>]*data-theme="${theme}"`).test(html)) fail('/', `cookie ${theme} not rendered`);
    if (!/private/.test(res.headers.get('cache-control') ?? '')) fail('/', 'themed page is cacheable');
  }
  const bad = await get('/', { headers: { Cookie: 'ti-theme=%3Cx%3E' } });
  if (/<html[^>]*data-theme=/.test(bad.html)) fail('/', 'an unknown theme cookie value was rendered');
  const quick = await get('/quick?q=log4j');
  if (quick.res.status !== 200) fail('/quick', `status ${quick.res.status}`);
  else {
    const data = JSON.parse(quick.html);
    if (!Array.isArray(data.hits) || data.hits.length > 8) fail('/quick', 'bad hits list');
  }
}

async function runChecks() {
  let stylesheet;
  for (const [path, title] of PAGES) {
    const { res, html } = await get(path);
    checkDocument(path, res, html, { title });
    if (path === '/') {
      stylesheet = html.match(/<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"/)?.[1];
      if (!html.includes('href="/privacy"')) fail(path, 'footer has no /privacy link');
    }
  }
  if (PRIVACY_UNFINISHED) {
    const { res } = await get('/privacy');
    if (res.status !== 503)
      fail('/privacy', `status ${res.status}, wanted 503 while [[OWNER: decisions remain`);
  }

  {
    const path = '/e/CVE-2025-3248';
    const { html } = await get(path);
    const fixture = JSON.parse(readFileSync(join(WEB_DIR, 'app/data/fixtures/entries.json'), 'utf8')).find(
      (e) => e.key === 'CVE-2025-3248',
    );
    if (!html.includes(fixture.summary)) fail(path, 'summary not in the server HTML');
    if (!html.includes(fixture.title)) fail(path, 'title not in the server HTML');
    if (!html.includes('Sources and credits') || !html.includes('Source: CISA KEV'))
      fail(path, 'credits missing');
    if (!html.includes('9.8')) fail(path, 'CVSS 9.8 missing');
    if (!html.includes('Exploited in the wild')) fail(path, '"Exploited in the wild" missing');
    if (!html.includes('application/ld+json')) fail(path, 'JSON-LD missing');
  }

  await checkAccounts();
  await checkShell();

  for (const from of ['/e/cve-2025-3248', '/e/GHSA-c995-4fw3-j39m']) {
    const { res } = await get(from);
    const loc = res.headers.get('location') ?? '';
    if (res.status !== 301) fail(from, `status ${res.status}, wanted 301`);
    if (!loc.endsWith('/e/CVE-2025-3248')) fail(from, `redirects to "${loc}"`);
    if (!res.headers.get('content-security-policy')?.includes("'nonce-")) fail(from, 'redirect has no CSP');
    const robots = res.headers.get('x-robots-tag');
    if (!API_MODE && robots !== 'noindex') fail(from, 'redirect has no X-Robots-Tag: noindex');
    if (API_MODE && robots !== null) fail(from, `redirect has X-Robots-Tag "${robots}"`);
    if (res.headers.get('x-content-type-options') !== 'nosniff') fail(from, 'redirect has no nosniff');
  }

  for (const path of ['/e/CVE-1999-99999', '/no-such-page', '/index/ab', '/breach/no-such-breach', '/ops']) {
    const { res, html } = await get(path);
    checkDocument(path, res, html, { title: 'Not found', status: 404 });
  }

  if (API_MODE) {
    {
      const { res, html } = await get('/e/CVE-1900-0500');
      checkDocument('/e/CVE-1900-0500', res, html, { title: 'The index is not answering', status: 502 });
    }
    const { res, html } = await get('/sitemap.xml');
    if (res.status !== 200) fail('/sitemap.xml', `status ${res.status}`);
    if (!(res.headers.get('content-type') ?? '').includes('xml')) fail('/sitemap.xml', 'not XML');
    if (res.headers.get('x-content-type-options') !== 'nosniff') fail('/sitemap.xml', 'no nosniff');
    if (!html.includes('<urlset')) fail('/sitemap.xml', 'no <urlset>');
  } else {
    const { res } = await get('/sitemap.xml');
    if (res.status !== 404) fail('/sitemap.xml', `status ${res.status}, wanted 404 in fixtures mode`);
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
  const args = ['dev', '-c', config];
  if (API_MODE) {
    args.push('-c', join(WEB_DIR, 'scripts', 'stub-api', 'wrangler.jsonc'));
    // Dummy keys, no network: they only switch Clerk on so the CSP and routes can be checked.
    args.push('--var', `CLERK_PUBLISHABLE_KEY:${CLERK_KEY}`, '--var', `CLERK_SECRET_KEY:${CLERK_SECRET}`);
  } else args.push('--var', 'DATA_SOURCE:fixtures');
  // The production config has a custom-domain route, and `wrangler dev` would otherwise present requests as
  // coming from that host. The smoke test talks to 127.0.0.1, so say so.
  args.push('--ip', '127.0.0.1', '--port', String(PORT), '--local-upstream', `127.0.0.1:${PORT}`);
  const child = spawn(join(ROOT, 'node_modules', '.bin', 'wrangler'), args, {
    cwd: ROOT,
    detached: true,
    stdio: ['ignore', 'inherit', 'inherit'],
    env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1' },
  });
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
  console.log(`✓ smoke (${MODE}): ${PAGES.length + 13} routes and the build checks passed`);
}

async function both() {
  for (const mode of ['fixtures', 'api']) {
    const code = await new Promise((done) => {
      const p = spawn(process.execPath, [fileURLToPath(import.meta.url), '--mode', mode], {
        stdio: 'inherit',
      });
      p.on('exit', (c) => done(c ?? 1));
    });
    if (code !== 0) process.exit(code);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (MODE === 'both') await both();
  else await main();
}
