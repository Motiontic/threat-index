// Smoke check of a DEPLOYED ti-web and ti-api (staging or a local pair). Read-only: GET requests, no
// credentials, no writes, at most 40 requests, one at a time.
//
//   node scripts/smoke-staging.mjs --web <url> --api <url> [--mcp on|off]   (or TI_WEB_URL and TI_API_URL)
//
// `--mcp on` (the default) expects MCP switched on, as in staging. `--mcp off` expects it switched off
// (MCP_ENABLED = "0", as in production until launch): the four MCP rows must answer 404 and set no cookie, and
// the If-None-Match row is skipped. Every other row is the same in both modes.
//
// Prints a `check | status | result` table and exits 1 when any row fails.
import { fileURLToPath } from 'node:url';

const MAX_REQUESTS = 43;
const trim = (u) => u.replace(/\/+$/, '');

/** One row per check. `fetchImpl` is `fetch`-shaped, so tests can pass a fake. */
export async function runSmoke(fetchImpl, { web, api, mcp = 'on' }) {
  if (mcp !== 'on' && mcp !== 'off') throw new Error('mcp must be on or off');
  const rows = [];
  let requests = 0;
  const get = async (base, path, { method = 'GET', headers = {}, body } = {}) => {
    if (++requests > MAX_REQUESTS) throw new Error(`more than ${MAX_REQUESTS} requests`);
    return fetchImpl(`${trim(base)}${path}`, {
      method,
      redirect: 'manual',
      headers: { Accept: '*/*', ...headers },
      ...(body !== undefined ? { body } : {}),
    });
  };

  async function check(
    label,
    base,
    path,
    {
      status,
      json = false,
      web: isWeb = false,
      hits = false,
      noCookie = false,
      contentType,
      expect,
      method,
      headers,
      body,
    },
  ) {
    let res;
    try {
      res = await get(base, path, { method, headers, body });
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
    if (noCookie && h('set-cookie')) problems.push('sets a cookie');
    if (json && !(h('content-type') ?? '').includes('application/json')) problems.push('not JSON');
    if (contentType && (h('content-type') ?? '').split(';')[0].trim().toLowerCase() !== contentType)
      problems.push(`content-type is not ${contentType}`);
    if (expect) {
      try {
        const why = await expect(res.clone());
        if (why) problems.push(why);
      } catch (err) {
        problems.push(`check threw: ${err.message}`);
      }
    }
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

  const skip = (label, result = 'skip: no record found') => rows.push({ check: label, status: '-', result });

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
  const wellKnown = '/.well-known/oauth-protected-resource/mcp';
  if (mcp === 'off') {
    // MCP switched off: ti-web answers 404 for all four, and sets no cookie.
    const off = { status: 404, noCookie: true };
    await check('web /mcp (MCP off)', web, '/mcp', off);
    await check(`web ${wellKnown} (MCP off)`, web, wellKnown, off);
    await check('web /mcp/server-card (MCP off)', web, '/mcp/server-card', off);
    await check('web POST /mcp (no token) (MCP off)', web, '/mcp', {
      ...off,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: '{}',
    });
    skip('web /mcp/server-card (If-None-Match) (MCP off)', 'skip: MCP off');
  } else {
    // MCP, forwarded by ti-web to ti-mcp (switched on in staging). Not pages, so no Permissions-Policy requirement
    // beyond what ti-mcp sets; the headers are checked and no cookie may be set.
    await check('web /mcp', web, '/mcp', { status: 405, noCookie: true });
    await check(`web ${wellKnown}`, web, wellKnown, {
      status: 200,
      json: true,
      noCookie: true,
      expect: async (res) => {
        const d = await res.json();
        if (d.resource !== `${trim(web)}/mcp`) return 'resource is not <web>/mcp';
        if (!Array.isArray(d.authorization_servers) || d.authorization_servers.length !== 1)
          return 'authorization_servers is not one entry';
        if (JSON.stringify(d.bearer_methods_supported) !== '["header"]')
          return 'bearer_methods_supported is not ["header"]';
        if (JSON.stringify(d).includes('offline_access')) return 'offline_access is listed';
        return null;
      },
    });
    const card = await check('web /mcp/server-card', web, '/mcp/server-card', {
      status: 200,
      contentType: 'application/mcp-server-card+json',
      noCookie: true,
      expect: async (res) => {
        if (res.headers.get('access-control-allow-origin') !== '*')
          return 'no Access-Control-Allow-Origin: *';
        return res.headers.get('etag') ? null : 'no ETag';
      },
    });
    const etag = card?.headers.get('etag');
    if (etag)
      await check('web /mcp/server-card (If-None-Match)', web, '/mcp/server-card', {
        status: 304,
        noCookie: true,
        headers: { 'If-None-Match': etag },
      });
    else skip('web /mcp/server-card (If-None-Match)');
    // No token: 401 with a challenge that names the metadata document and scope, and no `error`.
    await check('web POST /mcp (no token)', web, '/mcp', {
      status: 401,
      json: true,
      noCookie: true,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/list',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } },
      }),
      expect: async (res) => {
        const c = res.headers.get('www-authenticate') ?? '';
        if (!c.includes(`resource_metadata="${trim(web)}${wellKnown}"`))
          return 'challenge has no resource_metadata';
        if (!c.includes('scope="mti:read"')) return 'challenge has no scope';
        return /error=/.test(c) ? 'challenge has an error=' : null;
      },
    });
  }

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
      'usage: node scripts/smoke-staging.mjs --web <url> --api <url> [--mcp on|off]  (or TI_WEB_URL and TI_API_URL)',
    );
    process.exit(2);
  }
  const mcp = arg('mcp') ?? 'on';
  if (mcp !== 'on' && mcp !== 'off') {
    console.error('--mcp must be on or off');
    process.exit(2);
  }
  const rows = await runSmoke(fetch, { web, api, mcp });
  console.log(formatTable(rows));
  const failed = rows.filter((r) => r.result.startsWith('fail')).length;
  console.log(failed ? `\n${failed} of ${rows.length} checks failed` : `\nall ${rows.length} checks passed`);
  process.exit(failed ? 1 : 0);
}
