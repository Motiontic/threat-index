// Smoke check of a DEPLOYED ti-web and ti-api (staging or a local pair). Read-only: GET requests, no
// credentials, no writes, at most 40 requests, one at a time.
//
//   node scripts/smoke-staging.mjs --web <url> --api <url>     (or TI_WEB_URL and TI_API_URL)
//
// Prints a `check | status | result` table and exits 1 when any row fails.
import { fileURLToPath } from 'node:url';

const MAX_REQUESTS = 40;
const trim = (u) => u.replace(/\/+$/, '');

/** One row per check. `fetchImpl` is `fetch`-shaped, so tests can pass a fake. */
export async function runSmoke(fetchImpl, { web, api }) {
  const rows = [];
  let requests = 0;
  const get = async (base, path) => {
    if (++requests > MAX_REQUESTS) throw new Error(`more than ${MAX_REQUESTS} requests`);
    return fetchImpl(`${trim(base)}${path}`, { redirect: 'manual', headers: { Accept: '*/*' } });
  };

  async function check(label, base, path, { status, json = false, web: isWeb = false, hits = false }) {
    let res;
    try {
      res = await get(base, path);
    } catch (err) {
      rows.push({ check: label, status: '-', result: `fail: ${err.message}` });
      return null;
    }
    const h = (n) => res.headers.get(n);
    const problems = [];
    if (res.status !== status) problems.push(`status ${res.status}, wanted ${status}`);
    if (!h('x-request-id')) problems.push('no x-request-id');
    if (!/max-age=\d{7,}/.test(h('strict-transport-security') ?? '')) problems.push('no HSTS');
    if (h('x-content-type-options') !== 'nosniff') problems.push('no nosniff');
    const framed =
      /frame-ancestors/i.test(h('content-security-policy') ?? '') ||
      /^deny$/i.test(h('x-frame-options') ?? '');
    if (!framed) problems.push('no frame protection');
    if (!h('referrer-policy')) problems.push('no Referrer-Policy');
    if (isWeb && !h('permissions-policy')) problems.push('no Permissions-Policy');
    if (json && !(h('content-type') ?? '').includes('application/json')) problems.push('not JSON');
    if (hits && res.status === status) {
      try {
        const n = (await res.clone().json()).hits?.length ?? 0;
        if (n < 1) problems.push('no hits');
      } catch {
        problems.push('no hits');
      }
    }
    rows.push({
      check: label,
      status: res.status,
      result: problems.length ? `fail: ${problems.join('; ')}` : 'ok',
    });
    return res;
  }

  const skip = (label) => rows.push({ check: label, status: '-', result: 'skip: no record found' });

  // The first hit of a search gives a real record key for the entry checks.
  let key = null;
  const search = await check('api /v1/search?q=log4j', api, '/v1/search?q=log4j', {
    status: 200,
    json: true,
  });
  if (search?.status === 200) {
    try {
      key = (await search.json()).hits?.[0]?.key ?? null;
    } catch {
      key = null;
    }
  }

  // A very common term: the nightly index must still return results for it.
  await check('api /v1/search?q=apache', api, '/v1/search?q=apache', { status: 200, json: true, hits: true });

  await check('web /', web, '/', { status: 200, web: true });
  await check('web /search?q=log4j', web, '/search?q=log4j', { status: 200, web: true });
  if (key) await check('web /e/<key>', web, `/e/${encodeURIComponent(key)}`, { status: 200, web: true });
  else skip('web /e/<key>');
  for (const p of ['/index', '/index/a', '/sources', '/breaches', '/incidents', '/techniques', '/sign-in'])
    await check(`web ${p}`, web, p, { status: 200, web: true });
  await check('web missing page', web, '/no-such-page-smoke', { status: 404, web: true });
  await check('web /ops', web, '/ops', { status: 404, web: true });

  await check('api /v1/health', api, '/v1/health', { status: 200, json: true });
  if (key)
    await check('api /v1/entries/<key>', api, `/v1/entries/${encodeURIComponent(key)}`, {
      status: 200,
      json: true,
    });
  else skip('api /v1/entries/<key>');
  for (const p of ['/v1/index/a', '/v1/sources', '/v1/breaches', '/v1/incidents', '/v1/techniques'])
    await check(`api ${p}`, api, p, { status: 200, json: true });
  await check('api /v1/me', api, '/v1/me', { status: 401, json: true });
  await check('api /v1/admin/ops', api, '/v1/admin/ops', { status: 403, json: true });
  await check('api unknown path', api, '/v1/no-such-route-smoke', { status: 404, json: true });

  return rows;
}

export function formatTable(rows) {
  const w = Math.max(5, ...rows.map((r) => r.check.length));
  const line = (a, b, c) => `${a.padEnd(w)} | ${String(b).padEnd(6)} | ${c}`;
  return [
    line('check', 'status', 'result'),
    line('-'.repeat(w), '------', '------'),
    ...rows.map((r) => line(r.check, r.status, r.result)),
  ].join('\n');
}

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const web = arg('web') ?? process.env.TI_WEB_URL;
  const api = arg('api') ?? process.env.TI_API_URL;
  if (!web || !api) {
    console.error(
      'usage: node scripts/smoke-staging.mjs --web <url> --api <url>  (or TI_WEB_URL and TI_API_URL)',
    );
    process.exit(2);
  }
  const rows = await runSmoke(fetch, { web, api });
  console.log(formatTable(rows));
  const failed = rows.filter((r) => r.result.startsWith('fail')).length;
  console.log(failed ? `\n${failed} of ${rows.length} checks failed` : `\nall ${rows.length} checks passed`);
  process.exit(failed ? 1 : 0);
}
