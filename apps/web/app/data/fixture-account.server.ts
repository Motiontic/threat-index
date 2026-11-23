// In-memory `/v1/me*` routes and the signed-in entry view, for fixtures mode (fake auth only). They accept only
// `Authorization: Bearer fake.<user>`, mirror the real API's status codes and limits, and keep state per user
// in this isolate's memory, which is all QA and tests need.
import {
  type AlertSettings,
  MAX_DISPLAY_NAME_CHARS,
  MAX_SAVED_SEARCH_NAME_CHARS,
  MAX_SAVED_SEARCHES,
  MAX_WATCH_ITEMS,
  type Me,
  type SavedSearch,
  type SavedSearchParams,
  type WatchItem,
} from '@ti/core/account';
import type { EntryFull } from '@ti/core/api';
import { normaliseId } from '@ti/core/ids';
import { FAKE_TOKEN_PREFIX, FAKE_USER } from '../lib/fake-auth.server';
import { FIXTURE_ENTRIES, type FixtureEntry } from './fixtures.server';

interface UserState {
  displayName: string | null;
  alerts: AlertSettings;
  watch: Map<string, WatchItem>;
  saved: SavedSearch[];
}

const users = new Map<string, UserState>();

export function resetFixtureAccounts(): void {
  users.clear();
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
const error = (status: number, code: string) => json({ error: code }, status);

/** The fake user behind a `Bearer fake.<user>` header, or null. */
export function fakeUserOf(request: Request): string | null {
  const m = /^Bearer (.+)$/.exec(request.headers.get('authorization') ?? '');
  const token = m?.[1];
  if (!token?.startsWith(FAKE_TOKEN_PREFIX)) return null;
  const user = token.slice(FAKE_TOKEN_PREFIX.length);
  return FAKE_USER.test(user) ? user : null;
}

function stateOf(user: string): UserState {
  let s = users.get(user);
  if (!s) {
    s = {
      displayName: null,
      alerts: { instant: true, digest: 'weekly', digestWeekday: 1 },
      watch: new Map(),
      saved: [],
    };
    users.set(user, s);
  }
  return s;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ID = /^[A-Za-z0-9._:-]+$/;
const hasControl = (s: string) => [...s].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127);

const toMe = (user: string, s: UserState): Me => ({
  userId: `user_${user}`,
  email: `${user}@example.test`,
  displayName: s.displayName,
  alerts: { ...s.alerts },
});

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const v = JSON.parse(await request.text());
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function findEntry(id: string): FixtureEntry | undefined {
  const wanted = normaliseId(id);
  return FIXTURE_ENTRIES.find((e) => e.key === wanted || e.aliases.some((a) => normaliseId(a) === wanted));
}

async function patchMe(request: Request, s: UserState, user: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return error(400, 'bad_request');
  const allowed = new Set(['displayName', 'alerts']);
  if (Object.keys(body).some((k) => !allowed.has(k))) return error(400, 'bad_request');
  const next = { displayName: s.displayName, alerts: { ...s.alerts } };
  if ('displayName' in body) {
    const n = body.displayName;
    if (n === null) next.displayName = null;
    else if (typeof n === 'string' && n.trim().length <= MAX_DISPLAY_NAME_CHARS && !hasControl(n))
      next.displayName = n.trim() === '' ? null : n.trim();
    else return error(400, 'bad_request');
  }
  if ('alerts' in body) {
    const a = body.alerts;
    if (typeof a !== 'object' || a === null || Array.isArray(a)) return error(400, 'bad_request');
    const o = a as Record<string, unknown>;
    for (const k of Object.keys(o)) if (!['instant', 'digest', 'digestWeekday'].includes(k)) return error(400, 'bad_request');
    if ('instant' in o) {
      if (typeof o.instant !== 'boolean') return error(400, 'bad_request');
      next.alerts.instant = o.instant;
    }
    if ('digest' in o) {
      if (o.digest !== 'daily' && o.digest !== 'weekly' && o.digest !== 'off') return error(400, 'bad_request');
      next.alerts.digest = o.digest;
    }
    if ('digestWeekday' in o) {
      const d = o.digestWeekday;
      if (typeof d !== 'number' || !Number.isInteger(d) || d < 0 || d > 6) return error(400, 'bad_request');
      next.alerts.digestWeekday = d;
    }
  }
  s.displayName = next.displayName;
  s.alerts = next.alerts;
  return json(toMe(user, s));
}

async function watchRoute(request: Request, s: UserState, id: string): Promise<Response> {
  if (!ID.test(id) || id.length > 100) return error(400, 'bad_id');
  if (request.method === 'PUT') {
    const entry = findEntry(id);
    if (!entry) return error(404, 'not_found');
    const body = request.headers.get('content-length') === '0' ? {} : ((await readBody(request)) ?? null);
    if (body === null) return error(400, 'bad_request');
    if (Object.keys(body).some((k) => k !== 'alertsOn')) return error(400, 'bad_request');
    if ('alertsOn' in body && typeof body.alertsOn !== 'boolean') return error(400, 'bad_request');
    const existing = s.watch.get(entry.key);
    if (!existing && s.watch.size >= MAX_WATCH_ITEMS) return error(409, 'limit_reached');
    const item: WatchItem = existing ?? {
      entryKey: entry.key,
      title: entry.title,
      alertsOn: body.alertsOn !== false,
      createdAt: new Date().toISOString(),
    };
    if (typeof body.alertsOn === 'boolean') item.alertsOn = body.alertsOn;
    s.watch.set(entry.key, item);
    return json(item);
  }
  if (request.method === 'DELETE') {
    const entry = findEntry(id);
    if (!entry || !s.watch.delete(entry.key)) return error(404, 'not_found');
    return json({ ok: true });
  }
  return error(405, 'method_not_allowed');
}

const PARAM_KEYS = ['type', 'sig', 'sev', 'year'] as const;

async function savedRoute(request: Request, s: UserState, id: string | null): Promise<Response> {
  if (id === null && request.method === 'GET')
    return json({ items: [...s.saved].reverse(), limit: MAX_SAVED_SEARCHES });
  if (id === null && request.method === 'POST') {
    const body = await readBody(request);
    if (!body) return error(400, 'bad_request');
    const { name, query, params, alertsOn, ...rest } = body;
    if (Object.keys(rest).length > 0) return error(400, 'bad_request');
    if (typeof name !== 'string' || name.trim() === '' || name.trim().length > MAX_SAVED_SEARCH_NAME_CHARS)
      return error(400, 'bad_request');
    if (typeof query !== 'string' || query.trim().length > 200) return error(400, 'bad_request');
    if (alertsOn !== undefined && typeof alertsOn !== 'boolean') return error(400, 'bad_request');
    const stored: SavedSearchParams = {};
    if (params !== undefined) {
      if (typeof params !== 'object' || params === null || Array.isArray(params)) return error(400, 'bad_request');
      const p = params as Record<string, unknown>;
      for (const k of Object.keys(p)) if (![...PARAM_KEYS, 'sort'].includes(k)) return error(400, 'bad_request');
      for (const k of PARAM_KEYS) {
        const v = p[k];
        if (v === undefined) continue;
        if (!Array.isArray(v) || v.length > 12 || v.some((x) => typeof x !== 'string' || x.length > 32))
          return error(400, 'bad_request');
        stored[k] = v as string[];
      }
      if (p.sort !== undefined) {
        if (p.sort !== 'rel' && p.sort !== 'new') return error(400, 'bad_request');
        stored.sort = p.sort;
      }
    }
    if (s.saved.length >= MAX_SAVED_SEARCHES) return error(409, 'limit_reached');
    const row: SavedSearch = {
      id: crypto.randomUUID(),
      name: name.trim(),
      query: query.trim(),
      params: stored,
      alertsOn: alertsOn === true,
      createdAt: new Date().toISOString(),
    };
    s.saved.push(row);
    return json(row, 201);
  }
  if (id !== null && request.method === 'DELETE') {
    if (!UUID.test(id)) return error(400, 'bad_id');
    const at = s.saved.findIndex((r) => r.id === id);
    if (at < 0) return error(404, 'not_found');
    s.saved.splice(at, 1);
    return json({ ok: true });
  }
  return error(405, 'method_not_allowed');
}

/** `/v1/me*` for the fake user behind the bearer token. */
export async function fixtureAccountApi(request: Request, path: string): Promise<Response> {
  const user = fakeUserOf(request);
  if (!user) return error(401, 'sign_in_required');
  const s = stateOf(user);
  if (path === '/v1/me') {
    if (request.method === 'GET') return json(toMe(user, s));
    if (request.method === 'PATCH') return patchMe(request, s, user);
    if (request.method === 'DELETE') {
      users.delete(user);
      return json({ deleted: true });
    }
    return error(405, 'method_not_allowed');
  }
  if (path === '/v1/me/watch') {
    return request.method === 'GET'
      ? json({ items: [...s.watch.values()], limit: MAX_WATCH_ITEMS })
      : error(405, 'method_not_allowed');
  }
  const watchId = /^\/v1\/me\/watch\/([^/]+)$/.exec(path)?.[1];
  if (watchId !== undefined) {
    try {
      return await watchRoute(request, s, decodeURIComponent(watchId));
    } catch {
      return error(400, 'bad_id');
    }
  }
  if (path === '/v1/me/saved-searches') return savedRoute(request, s, null);
  const savedId = /^\/v1\/me\/saved-searches\/([^/]+)$/.exec(path)?.[1];
  if (savedId !== undefined) return savedRoute(request, s, decodeURIComponent(savedId));
  return error(404, 'not_found');
}

/** The full view, with a signal of every kind for vulnerabilities, plus one unknown kind. */
export function fixtureFullEntry(e: FixtureEntry, preview: EntryFull): EntryFull {
  const vuln = e.type === 'vuln';
  const first = e.published ?? '2025-01-01';
  const signals: EntryFull['signals'] = [];
  if (vuln) {
    if (e.kev_added)
      signals.push({
        kind: 'exploited_wild',
        source: 'cisa-kev',
        ref: e.key,
        firstSeen: e.kev_added,
        url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      });
    if (e.kev_added)
      signals.push({ kind: 'ransomware', source: 'cisa-kev', ref: 'Known ransomware use', firstSeen: e.kev_added });
    signals.push(
      {
        kind: 'public_exploit',
        source: 'exploit-db',
        ref: 'EDB-00000',
        firstSeen: first,
        url: 'https://www.exploit-db.com/',
      },
      { kind: 'poc', source: 'poc-in-github', ref: 'example/poc', firstSeen: first, url: 'https://github.com/' },
      { kind: 'detection', source: 'nuclei', ref: `${e.key.toLowerCase()}.yaml`, firstSeen: first },
      { kind: 'sighting', source: 'gcve', ref: 'sample sighting', firstSeen: first },
    );
  }
  return {
    ...preview,
    ...(vuln ? { epss: 0.42 } : {}),
    cwe: vuln ? ['CWE-306'] : [],
    advisories: vuln
      ? [
          {
            source: 'github-advisory-db',
            sourceId: e.aliases[0] ?? e.key,
            status: 'published',
            url: 'https://github.com/advisories',
            published: first,
            display: 'full',
            affected: [{ ecosystem: 'PyPI', name: 'example-package', introduced: '0', fixed: '1.2.3' }],
          },
          { source: 'nvd', sourceId: e.key, status: 'analyzed', url: 'https://nvd.nist.gov/', display: 'link' },
          { source: 'withheld', sourceId: 'X-1', status: 'secret', display: 'hidden' },
        ]
      : [],
    signals,
    changes: [
      { kind: 'cvss', old: '9.0', new: String(e.cvss ?? '9.8'), at: `${first}T12:00:00Z`, source: 'nvd' },
      ...(e.kev_added ? [{ kind: 'kev_added', new: e.kev_added, at: `${e.kev_added}T06:00:00Z`, source: 'cisa-kev' }] : []),
    ],
  };
}
