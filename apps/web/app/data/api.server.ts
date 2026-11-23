// The only file that calls `fetch`. Every method asks ti-api over the service binding for a PREVIEW:
// the request carries no visitor header (no Cookie, no Authorization) and the query string is built here from
// validated values, so the API's answer, and any caching of it, never varies on the visitor.
import {
  GuardError,
  guardApiError,
  guardEntryResponse,
  guardIndexLetter,
  guardSearchResponse,
  guardSources,
} from './guards';
import type { DataMode } from './mode.server';
import type { SearchParams, SiteData } from './types';

export const API_ORIGIN = 'https://ti-api.internal';
export const TIMEOUT_MS = 5000;
export const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** The API did not give a usable answer: 5xx, timeout, network error, oversized body or failed guard. */
export class ApiUnavailable extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ApiUnavailable';
  }
}

/** The API answered 400. `message` is its `ApiError.error`. */
export class ApiBadRequest extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiBadRequest';
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
