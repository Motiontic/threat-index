/**
 * Fetching one document for the sandbox jobs: `https:` only, at most 5 redirects, 3 retries on a network error
 * or a 5xx, and a polite wait on a 429. Errors never carry the URL or a body.
 */
import { MAX_REDIRECTS, USER_AGENT } from './download.ts';

export const MAX_DOC_BYTES = 10 * 1024 * 1024;
const RETRIES = 3;
const DEFAULT_RETRY_AFTER_S = 30;
const MAX_RETRY_AFTER_S = 60;

export interface FetchDeps {
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function assertHttps(url: string): void {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error('fetch refused: not a URL');
  }
  if (u.protocol !== 'https:') throw new Error('fetch refused: only https: URLs are allowed');
}

/** `Retry-After` in seconds (a number, or an HTTP date), clamped to 60; 30 when absent or unreadable. */
export function retryAfterSeconds(header: string | null, now: number): number {
  let s = Number.NaN;
  if (header) {
    s = /^\d+$/.test(header.trim()) ? Number(header) : (Date.parse(header) - now) / 1000;
  }
  if (Number.isNaN(s)) s = DEFAULT_RETRY_AFTER_S;
  return Math.min(MAX_RETRY_AFTER_S, Math.max(0, s));
}

/**
 * GETs `url` and returns the response (body unread) once it is a 2xx. `404` and `410` return null when
 * `goneIsNull`. Any other 4xx throws. A 429 waits and counts as a retry.
 */
export async function fetchDocument(
  url: string,
  deps: FetchDeps = {},
  opts: { goneIsNull?: boolean } = {},
): Promise<Response | null> {
  const doFetch = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? defaultSleep;
  assertHttps(url);
  let lastError = '';
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    let current = url;
    let res: Response | undefined;
    try {
      for (let hops = 0; ; hops++) {
        assertHttps(current);
        res = await doFetch(current, { redirect: 'manual', headers: { 'user-agent': USER_AGENT } });
        if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
          if (hops >= MAX_REDIRECTS) throw new Error('fetch refused: too many redirects');
          current = new URL(res.headers.get('location') as string, current).href;
          await res.body?.cancel();
          continue;
        }
        break;
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('fetch refused')) throw err;
      lastError = 'network error';
      if (attempt < RETRIES) await sleep(500 * 2 ** attempt);
      continue;
    }
    if (res.status === 429) {
      lastError = 'status 429';
      const wait = retryAfterSeconds(res.headers.get('retry-after'), Date.now());
      await res.body?.cancel();
      if (attempt < RETRIES) await sleep(wait * 1000);
      continue;
    }
    if (res.status >= 500) {
      lastError = `status ${res.status}`;
      await res.body?.cancel();
      if (attempt < RETRIES) await sleep(500 * 2 ** attempt);
      continue;
    }
    if ((res.status === 404 || res.status === 410) && opts.goneIsNull) {
      await res.body?.cancel();
      return null;
    }
    if (!res.ok || !res.body) {
      await res.body?.cancel();
      throw new Error(`fetch refused: status ${res.status}`);
    }
    return res;
  }
  throw new Error(`fetch failed after retries: ${lastError}`);
}

/** The body as text, or null when it is over `max` bytes (the rest of the body is dropped). */
export async function readTextLimited(res: Response, max = MAX_DOC_BYTES): Promise<string | null> {
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > max) {
    await res.body?.cancel();
    return null;
  }
  const reader = (res.body as ReadableStream<Uint8Array>).getReader();
  const parts: Uint8Array[] = [];
  let seen = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    seen += value.byteLength;
    if (seen > max) {
      await reader.cancel();
      return null;
    }
    parts.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(parts));
}
