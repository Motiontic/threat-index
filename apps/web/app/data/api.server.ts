// The only file that calls `fetch`. Every method asks ti-api over the service binding for a PREVIEW:
// the request carries no visitor header (no Cookie, no Authorization; only a request id and a signed IP) and the query string is built here from
// validated values, so the API's answer, and any caching of it, never varies on the visitor.
import type { MePatch, SavedSearchCreate } from '@ti/core/account';
import { CLIENT_IP_HEADER, CLIENT_SIG_HEADER, CLIENT_TS_HEADER, signClientIp } from '@ti/core/edge';
import { REQUEST_ID_HEADER } from '@ti/core/log';
import {
  GuardError,
  guardApiError,
  guardEntryFull,
  guardEntryResponse,
  guardIndexLetter,
  guardMe,
  guardSavedList,
  guardSavedSearch,
  guardSearchResponse,
  guardSources,
  guardWatchItem,
  guardWatchList,
} from './guards';
import type { DataMode } from './mode.server';
import { guardOps } from './ops-guard';
import type { AccountClient, SearchParams, SiteData, WorldQuery } from './types';
import {
  guardBreachDetail,
  guardBreachList,
  guardIncidentDetail,
  guardIncidentList,
  guardTechniqueDetail,
  guardTechniqueList,
} from './world-guards';

export const API_ORIGIN = 'https://ti-api.internal';
export const TIMEOUT_MS = 5000;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** The API did not give a usable answer: 5xx, timeout, network error, oversized body or failed guard. */
export class ApiUnavailable extends Error {
  /** The HTTP status the API answered, when it answered. */
  readonly status?: number;
  constructor(message: string, options?: { cause?: unknown; status?: number }) {
    super(message, options);
    this.name = 'ApiUnavailable';
    if (options?.status !== undefined) this.status = options.status;
  }
}

/** The API answered 400. `message` is its `ApiError.error`. */
export class ApiBadRequest extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiBadRequest';
  }
}

/** The API answered 401: there is no valid session. */
export class SignInRequired extends Error {
  constructor() {
    super('sign in required');
    this.name = 'SignInRequired';
  }
}

/** The API answered 409. `error` is its `ApiError.error` (`limit_reached`). */
export class ApiConflict extends Error {
  constructor(readonly error: string) {
    super(error);
    this.name = 'ApiConflict';
  }
}

/** A mutation targeted something the API does not have (404). */
export class NotFound extends Error {
  constructor() {
    super('not found');
    this.name = 'NotFound';
  }
}

/** The API answered 429. `retryAfter` is its Retry-After in seconds (1 to 3600, default 60). */
export class ApiRateLimited extends Error {
  constructor(readonly retryAfter: number) {
    super('rate limited');
    this.name = 'ApiRateLimited';
  }
}

/** What the API may know about the visitor's request: a request id and, when known, their IP (signed). */
export interface ClientContext {
  requestId: string;
  ip: string | null;
}

export function parseRetryAfter(raw: string | null): number {
  const n = Number(raw);
  return raw !== null && Number.isInteger(n) && n >= 1 && n <= 3600 ? n : 60;
}

/**
 * The only headers that identify the request to the API: the request id, and, when `secret` is set and the IP
 * is known, the IP with an HMAC the API verifies. No Cookie, Authorization or other visitor header.
 */
export async function clientHeaders(
  ctx: ClientContext,
  secret: string | undefined,
  now: Date = new Date(),
): Promise<Record<string, string>> {
  const headers: Record<string, string> = { [REQUEST_ID_HEADER]: ctx.requestId };
  if (secret && ctx.ip) {
    const ts = Math.floor(now.getTime() / 1000);
    headers[CLIENT_IP_HEADER] = ctx.ip;
    headers[CLIENT_TS_HEADER] = String(ts);
    headers[CLIENT_SIG_HEADER] = await signClientIp(secret, ctx.ip, ts, ctx.requestId);
  }
  return headers;
}

/** The query string for a search, built field by field in a fixed order. */
export function searchQuery(params: SearchParams): string {
  const qs = new URLSearchParams();
  if (params.q) qs.set('q', params.q);
  for (const t of params.type ?? []) qs.append('type', t);
  for (const s of params.sig ?? []) qs.append('sig', s);
  if (params.sev) qs.set('sev', params.sev);
  if (params.year) qs.set('year', params.year);
  if (params.sort) qs.set('sort', params.sort);
  if (params.cursor) qs.set('cursor', params.cursor);
  const text = qs.toString();
  return text ? `?${text}` : '';
}

/** The query string for a world list, built field by field in a fixed order from validated values. */
export function worldQuery(query: WorldQuery): string {
  const qs = new URLSearchParams();
  if (query.q) qs.set('q', query.q);
  if (query.page && query.page > 1) qs.set('page', String(Math.trunc(query.page)));
  for (const k of query.kind ?? []) qs.append('kind', k);
  for (const f of query.framework ?? []) qs.append('framework', f);
  const text = qs.toString();
  return text ? `?${text}` : '';
}

async function readCapped(res: Response): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new ApiUnavailable('response too large');
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new ApiUnavailable('response too large');
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

export function createSiteData(
  api: Pick<Fetcher, 'fetch'>,
  mode: DataMode,
  client: ClientContext,
  edgeSecret?: string,
): SiteData {
  async function call(path: string, accept = 'application/json'): Promise<Response> {
    try {
      return await api.fetch(
        new Request(`${API_ORIGIN}${path}`, {
          method: 'GET',
          headers: { Accept: accept, ...(await clientHeaders(client, edgeSecret)) },
          signal: AbortSignal.timeout(TIMEOUT_MS),
        }),
      );
    } catch (err) {
      throw new ApiUnavailable(`ti-api request failed: ${path}`, { cause: err });
    }
  }

  /** 200 → parsed and guarded; 404 → null; 400 → ApiBadRequest; anything else → ApiUnavailable. */
  async function getJson<T>(path: string, guard: (v: unknown) => T): Promise<T | null> {
    const res = await call(path);
    try {
      if (res.status === 404) {
        await res.body?.cancel();
        return null;
      }
      if (res.status === 429) {
        await res.body?.cancel();
        throw new ApiRateLimited(parseRetryAfter(res.headers.get('retry-after')));
      }
      if (res.status === 400) {
        let message = 'Bad request';
        try {
          message = guardApiError(JSON.parse(await readCapped(res)));
        } catch {
          // keep the generic message
        }
        throw new ApiBadRequest(message);
      }
      if (res.status !== 200) {
        await res.body?.cancel();
        throw new ApiUnavailable(`ti-api answered ${res.status} for ${path}`);
      }
      return guard(JSON.parse(await readCapped(res)));
    } catch (err) {
      if (err instanceof ApiUnavailable || err instanceof ApiBadRequest || err instanceof ApiRateLimited)
        throw err;
      if (err instanceof GuardError || err instanceof SyntaxError)
        throw new ApiUnavailable(`ti-api sent an unusable body for ${path}`, { cause: err });
      throw new ApiUnavailable(`ti-api read failed for ${path}`, { cause: err });
    }
  }

  async function required<T>(path: string, guard: (v: unknown) => T): Promise<T> {
    const out = await getJson(path, guard);
    if (out === null) throw new ApiUnavailable(`ti-api answered 404 for ${path}`);
    return out;
  }

  return {
    mode,
    entry: (id) => getJson(`/v1/entries/${encodeURIComponent(id)}`, guardEntryResponse),
    search: (params) => required(`/v1/search${searchQuery(params)}`, guardSearchResponse),
    index: (letter, cursor) =>
      getJson(
        `/v1/index/${encodeURIComponent(letter)}${cursor ? `?${new URLSearchParams({ cursor })}` : ''}`,
        guardIndexLetter,
      ),
    sources: () => required('/v1/sources', guardSources),
    breaches: (query) => required(`/v1/breaches${worldQuery(query)}`, guardBreachList),
    breach: (key) => getJson(`/v1/breaches/${encodeURIComponent(key)}`, guardBreachDetail),
    incidents: (query) => required(`/v1/incidents${worldQuery(query)}`, guardIncidentList),
    incident: (source, id) =>
      getJson(`/v1/incidents/${encodeURIComponent(source)}/${encodeURIComponent(id)}`, guardIncidentDetail),
    techniques: (query) => required(`/v1/techniques${worldQuery(query)}`, guardTechniqueList),
    technique: (id) => getJson(`/v1/techniques/${encodeURIComponent(id)}`, guardTechniqueDetail),
    async sitemap() {
      const res = await call('/v1/sitemap.xml', 'application/xml');
      const type = res.headers.get('content-type') ?? '';
      if (res.status === 200 && /xml/i.test(type)) return res;
      await res.body?.cancel();
      return null;
    },
  };
}

/**
 * The account calls: the only requests that carry a visitor's identity, and only as `Authorization: Bearer`.
 * No Cookie and no other visitor header is ever sent. Same timeout, size cap and guards as the public client.
 */
export function createAccountClient(
  api: Pick<Fetcher, 'fetch'>,
  token: string,
  client: ClientContext,
  edgeSecret?: string,
): AccountClient {
  async function call(method: string, path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
      ...(await clientHeaders(client, edgeSecret)),
    };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    try {
      return await api.fetch(
        new Request(`${API_ORIGIN}${path}`, {
          method,
          headers,
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        }),
      );
    } catch (err) {
      throw new ApiUnavailable(`ti-api request failed: ${method} ${path}`, { cause: err });
    }
  }

  async function errorText(res: Response): Promise<string> {
    try {
      return guardApiError(JSON.parse(await readCapped(res)));
    } catch {
      return 'Bad request';
    }
  }

  /** 2xx → parsed and guarded; 404 → null (or NotFound for mutations); 401/409/400 → their errors. */
  async function run<T>(
    method: string,
    path: string,
    guard: (v: unknown) => T,
    options: { body?: unknown; notFound?: 'null' | 'throw'; ok?: number[]; forbidden?: 'null' } = {},
  ): Promise<T | null> {
    const res = await call(method, path, options.body);
    const ok = options.ok ?? [200];
    try {
      if (res.status === 401) {
        await res.body?.cancel();
        throw new SignInRequired();
      }
      if (res.status === 403 && options.forbidden === 'null') {
        await res.body?.cancel();
        return null;
      }
      if (res.status === 404) {
        await res.body?.cancel();
        if (options.notFound === 'throw') throw new NotFound();
        return null;
      }
      if (res.status === 429) {
        await res.body?.cancel();
        throw new ApiRateLimited(parseRetryAfter(res.headers.get('retry-after')));
      }
      if (res.status === 409) throw new ApiConflict(await errorText(res));
      if (res.status === 400) throw new ApiBadRequest(await errorText(res));
      if (!ok.includes(res.status)) {
        await res.body?.cancel();
        throw new ApiUnavailable(`ti-api answered ${res.status} for ${method} ${path}`, {
          status: res.status,
        });
      }
      return guard(JSON.parse(await readCapped(res)));
    } catch (err) {
      if (
        err instanceof ApiUnavailable ||
        err instanceof ApiBadRequest ||
        err instanceof ApiRateLimited ||
        err instanceof ApiConflict ||
        err instanceof SignInRequired ||
        err instanceof NotFound
      )
        throw err;
      if (err instanceof GuardError || err instanceof SyntaxError)
        throw new ApiUnavailable(`ti-api sent an unusable body for ${path}`, { cause: err });
      throw new ApiUnavailable(`ti-api read failed for ${path}`, { cause: err });
    }
  }

  const need = <T>(v: T | null): T => {
    if (v === null) throw new NotFound();
    return v;
  };
  const mutate = { notFound: 'throw' as const };
  const guardOk = (v: unknown) => {
    if (typeof v !== 'object' || v === null) throw new GuardError('response: not an object');
    return true as const;
  };

  return {
    me: async () => need(await run('GET', '/v1/me', guardMe)),
    patchMe: async (patch: MePatch) => need(await run('PATCH', '/v1/me', guardMe, { body: patch })),
    watchList: async () => need(await run('GET', '/v1/me/watch', guardWatchList)),
    watch: async (id, alertsOn) =>
      need(
        await run('PUT', `/v1/me/watch/${encodeURIComponent(id)}`, guardWatchItem, {
          body: alertsOn === undefined ? {} : { alertsOn },
          ...mutate,
        }),
      ),
    async unwatch(id) {
      await run('DELETE', `/v1/me/watch/${encodeURIComponent(id)}`, guardOk, mutate);
    },
    savedList: async () => need(await run('GET', '/v1/me/saved-searches', guardSavedList)),
    saveSearch: async (body: SavedSearchCreate) =>
      need(await run('POST', '/v1/me/saved-searches', guardSavedSearch, { body, ok: [200, 201] })),
    async deleteSearch(id) {
      await run('DELETE', `/v1/me/saved-searches/${encodeURIComponent(id)}`, guardOk, mutate);
    },
    async deleteAccount() {
      await run('DELETE', '/v1/me', guardOk, mutate);
    },
    entryFull: (id) => run('GET', `/v1/entries/${encodeURIComponent(id)}`, guardEntryFull),
    adminOps: () => run('GET', '/v1/admin/ops', guardOps, { forbidden: 'null' }),
  };
}
