// The only file that calls `fetch`. Every method asks ti-api over the service binding for a PREVIEW:
// the request carries no visitor header (no Cookie, no Authorization) and the query string is built here from
// validated values, so the API's answer, and any caching of it, never varies on the visitor.
import type { MePatch, SavedSearchCreate } from '@ti/core/account';
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
import type { AccountClient, SearchParams, SiteData } from './types';

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

export function createSiteData(api: Pick<Fetcher, 'fetch'>, mode: DataMode): SiteData {
  async function call(path: string, accept = 'application/json'): Promise<Response> {
    try {
      return await api.fetch(
        new Request(`${API_ORIGIN}${path}`, {
          method: 'GET',
          headers: { Accept: accept },
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
      if (err instanceof ApiUnavailable || err instanceof ApiBadRequest) throw err;
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
export function createAccountClient(api: Pick<Fetcher, 'fetch'>, token: string): AccountClient {
  async function call(method: string, path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { Accept: 'application/json', Authorization: `Bearer ${token}` };
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
    options: { body?: unknown; notFound?: 'null' | 'throw'; ok?: number[] } = {},
  ): Promise<T | null> {
    const res = await call(method, path, options.body);
    const ok = options.ok ?? [200];
    try {
      if (res.status === 401) {
        await res.body?.cancel();
        throw new SignInRequired();
      }
      if (res.status === 404) {
        await res.body?.cancel();
        if (options.notFound === 'throw') throw new NotFound();
        return null;
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
  };
}
