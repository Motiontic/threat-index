/**
 * The sandbox's side of the API. Every call is signed with the per-job key. For the data routes the signed
 * path is `pathname + search` exactly as sent, a GET signs the empty body, and a PUT signs its SHA-256 digest.
 * Error messages carry the route name and the status, never a URL, a query, a key or a body.
 */
import { SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';

export const MAX_URLS_PER_CALL = 50;
export const MAX_OBJECT_BYTES = 50 * 1024 * 1024;
export const ROWS_PAGE = 500;
const RETRIES = 3;

export type RowTable = 'vulns' | 'advisories' | 'signals';
export interface UploadFile {
  key: string;
  body: string | Uint8Array;
  contentType: string;
}
export type CompleteResult = { ok: true } | { ok: false; error: string };
export interface JobApi {
  uploadUrls(keys: string[]): Promise<{ key: string; url: string }[]>;
  upload(files: UploadFile[]): Promise<void>;
  complete(result: CompleteResult): Promise<void>;
  putObject(key: string, body: Uint8Array | string, contentType: string): Promise<void>;
  /** The object's bytes, or null when it does not exist. */
  getObject(key: string): Promise<Uint8Array | null>;
  list(prefix: string): AsyncIterable<{ key: string; size: number }>;
  rows(
    table: RowTable,
    opts?: { after?: string; limit?: number },
  ): Promise<{ rows: Record<string, unknown>[]; next: string | null }>;
  allRows(table: RowTable): AsyncIterable<Record<string, unknown>>;
}
export interface ClientDeps {
  fetch?: typeof fetch;
  now?: () => number; // ms
  sleep?: (ms: number) => Promise<void>;
}
interface JobAuth {
  id: string;
  apiBase: string;
  hmac: string;
}

const enc = new TextEncoder();

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function createJobApi(job: JobAuth, deps: ClientDeps = {}): JobApi {
  const doFetch = deps.fetch ?? fetch;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const base = `/internal/jobs/${job.id}`;

  /**
   * One signed call, retried on a network error or a 5xx. `target` is the path and query as sent.
   * A 404 returns null when `allow404` is set.
   */
  async function send(
    route: string,
    method: 'GET' | 'POST' | 'PUT',
    target: string,
    opts: {
      body?: string | Uint8Array;
      signedBody: string;
      headers?: Record<string, string>;
      allow404?: boolean;
    },
  ): Promise<Response | null> {
    // The signed string is what the server sees after URL parsing, so parse it the same way here.
    const parsed = new URL(`${job.apiBase}${target}`);
    const signedTarget = parsed.pathname + parsed.search;
    let lastError = '';
    for (let attempt = 0; attempt <= RETRIES; attempt++) {
      if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
      const ts = Math.floor(now() / 1000);
      let res: Response;
      try {
        res = await doFetch(parsed.href, {
          method,
          headers: {
            ...opts.headers,
            [TIMESTAMP_HEADER]: String(ts),
            [SIGNATURE_HEADER]: await signRequest(job.hmac, method, signedTarget, ts, opts.signedBody),
          },
          ...(opts.body !== undefined ? { body: opts.body as BodyInit } : {}),
        });
      } catch {
        lastError = 'network error';
        continue;
      }
      if (res.ok) return res;
      if (res.status >= 500) {
        lastError = `status ${res.status}`;
        continue;
      }
      if (res.status === 404 && opts.allow404) return null;
      throw new Error(`${route} refused: status ${res.status}`);
    }
    throw new Error(`${route} failed after retries: ${lastError}`);
  }

  async function call(route: 'upload-urls' | 'complete', payload: unknown): Promise<unknown> {
    const body = JSON.stringify(payload);
    const res = (await send(route, 'POST', `${base}/${route}`, {
      body,
      signedBody: body,
      headers: { 'content-type': 'application/json' },
    })) as Response;
    return res.json();
  }

  async function uploadUrls(keys: string[]) {
    const out: { key: string; url: string }[] = [];
    for (let i = 0; i < keys.length; i += MAX_URLS_PER_CALL) {
      const slice = keys.slice(i, i + MAX_URLS_PER_CALL);
      const res = (await call('upload-urls', { keys: slice })) as { urls?: { key: string; url: string }[] };
      for (const key of slice) {
        const hit = res.urls?.find((u) => u.key === key);
        if (!hit) throw new Error('upload-urls reply is missing a key');
        out.push(hit);
      }
    }
    return out;
  }

  const objectPath = (key: string) => `${base}/objects/${key.split('/').map(encodeURIComponent).join('/')}`;

  async function putObject(key: string, body: Uint8Array | string, contentType: string) {
    const bytes = typeof body === 'string' ? enc.encode(body) : body;
    if (bytes.byteLength > MAX_OBJECT_BYTES)
      throw new Error('put-object refused: body is over the size limit');
    const digest = await sha256Hex(bytes);
    await send('put-object', 'PUT', objectPath(key), {
      body: bytes,
      signedBody: digest,
      headers: {
        'content-type': contentType,
        'content-length': String(bytes.byteLength),
        'x-ti-content-sha256': digest,
      },
    });
  }

  async function getObject(key: string) {
    const res = await send('get-object', 'GET', objectPath(key), { signedBody: '', allow404: true });
    return res ? new Uint8Array(await res.arrayBuffer()) : null;
  }

  async function* list(prefix: string) {
    let cursor: string | null = null;
    do {
      const q = new URLSearchParams({ prefix });
      if (cursor) q.set('cursor', cursor);
      const res = (await send('list', 'GET', `${base}/list?${q}`, { signedBody: '' })) as Response;
      const page = (await res.json()) as { objects: { key: string; size: number }[]; cursor: string | null };
      for (const o of page.objects) yield o;
      cursor = page.cursor;
    } while (cursor);
  }

  async function rows(table: RowTable, opts: { after?: string; limit?: number } = {}) {
    const q = new URLSearchParams();
    if (opts.after) q.set('after', opts.after);
    if (opts.limit !== undefined) q.set('limit', String(opts.limit));
    const qs = q.size > 0 ? `?${q}` : '';
    const res = (await send('rows', 'GET', `${base}/rows/${table}${qs}`, { signedBody: '' })) as Response;
    return (await res.json()) as { rows: Record<string, unknown>[]; next: string | null };
  }

  async function* allRows(table: RowTable) {
    let after: string | undefined;
    do {
      const page = await rows(table, { ...(after ? { after } : {}), limit: ROWS_PAGE });
      for (const r of page.rows) yield r;
      after = page.next ?? undefined;
    } while (after);
  }

  return {
    uploadUrls,
    putObject,
    getObject,
    list,
    rows,
    allRows,
    async upload(files) {
      for (const f of files) await putObject(f.key, f.body, f.contentType);
    },
    async complete(result) {
      await call('complete', result);
    },
  };
}
