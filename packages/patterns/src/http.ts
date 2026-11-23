import type { CredentialName } from '@ti/core/types';
import { MAX_RETRY_AFTER_SECONDS, PatternError } from './errors';
import type { PatternContext } from './types';

/** The only way a pattern reaches the network. It calls `ctx.fetch` and nothing else. */
export const MAX_BODY_BYTES = 5 * 1024 * 1024;
export const MAX_INLINE_WAIT_MS = 10_000;
/** Connections a Worker may have awaiting headers at once. */
export const MAX_PARALLEL = 6;
export const MAX_REQUESTS_PER_STEP = 60;
export const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_RATE_LIMIT_WAIT_MS = 60_000;
const MAX_REDIRECTS = 3;

export interface RequestOptions {
  method?: 'GET' | 'HEAD';
  accept?: string;
  /** A validator from `validatorOf`: sent as `If-None-Match` (ETag) or `If-Modified-Since` (`lm:` prefix). */
  validator?: string | null;
  range?: { start: number; end: number };
  /** Sends `ctx.credentials[credential]` to the origin of `url` only. */
  auth?: { credential: CredentialName; header: string; scheme?: string };
  maxBytes?: number;
  timeoutMs?: number;
}

export interface HttpResult {
  url: string;
  status: number;
  notModified: boolean;
  headers: Headers;
  text: string;
  validator: string | null;
  truncated: boolean;
}

/** The ETag, else `lm:<Last-Modified>`, else null. */
export function validatorOf(headers: Headers): string | null {
  const etag = headers.get('etag');
  if (etag) return etag;
  const lm = headers.get('last-modified');
  return lm ? `lm:${lm}` : null;
}

interface State {
  count: number;
  active: number;
  waiters: Array<() => void>;
  tail: Promise<void>;
  started: boolean;
}
const STATES = new WeakMap<PatternContext, State>();

function stateOf(ctx: PatternContext): State {
  let st = STATES.get(ctx);
  if (!st) {
    st = { count: 0, active: 0, waiters: [], tail: Promise.resolve(), started: false };
    STATES.set(ctx, st);
  }
  return st;
}

export async function request(
  ctx: PatternContext,
  url: string,
  opts: RequestOptions = {},
): Promise<HttpResult> {
  if (!ctx.userAgent.trim()) throw new PatternError('a User-Agent with a contact is required', 'runtime');
  let origin: string;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('protocol');
    origin = u.origin;
  } catch {
    throw new PatternError('not a valid http(s) URL', 'runtime');
  }
  const st = stateOf(ctx);
  const perMinute = ctx.source.rateLimit?.perMinute;
  if (perMinute && perMinute > 0) {
    // One at a time, spaced apart.
    const prev = st.tail;
    let release: () => void = () => {};
    st.tail = new Promise<void>((r) => {
      release = r;
    });
    try {
      await prev;
      if (st.started) await ctx.wait(Math.ceil(60_000 / perMinute));
      st.started = true;
      return await withRateLimitRetry(ctx, st, url, origin, opts);
    } finally {
      release();
    }
  }
  while (st.active >= MAX_PARALLEL) await new Promise<void>((r) => st.waiters.push(r));
  st.active++;
  try {
    return await withRateLimitRetry(ctx, st, url, origin, opts);
  } finally {
    st.active--;
    st.waiters.shift()?.();
  }
}

function isRateLimited(res: Response): boolean {
  if (res.status === 429 || res.status === 503) return true;
  return (
    res.status === 403 && (res.headers.has('retry-after') || res.headers.get('x-ratelimit-remaining') === '0')
  );
}

function rateLimitWaitMs(ctx: PatternContext, headers: Headers): number {
  const ra = headers.get('retry-after');
  if (ra) {
    const secs = Number(ra);
    if (Number.isFinite(secs) && secs >= 0) return secs * 1000;
    const at = Date.parse(ra);
    if (!Number.isNaN(at)) return Math.max(0, at - ctx.now().getTime());
  }
  const reset = Number(headers.get('x-ratelimit-reset'));
  if (headers.get('x-ratelimit-reset') && Number.isFinite(reset))
    return Math.max(0, reset * 1000 - ctx.now().getTime());
  return DEFAULT_RATE_LIMIT_WAIT_MS;
}

async function withRateLimitRetry(
  ctx: PatternContext,
  st: State,
  url: string,
  origin: string,
  opts: RequestOptions,
): Promise<HttpResult> {
  for (let attempt = 0; ; attempt++) {
    const out = await once(ctx, st, url, origin, opts);
    if (!('limited' in out)) return out;
    const waitMs = rateLimitWaitMs(ctx, out.limited.headers);
    if (attempt === 0 && waitMs <= MAX_INLINE_WAIT_MS) {
      await ctx.wait(waitMs);
      continue;
    }
    throw new PatternError(`rate limited (${out.limited.status})`, 'rate-limited', {
      status: out.limited.status,
      retryAfterSeconds: Math.min(Math.ceil(waitMs / 1000), MAX_RETRY_AFTER_SECONDS),
    });
  }
}

type Once = HttpResult | { limited: { status: number; headers: Headers } };

async function once(
  ctx: PatternContext,
  st: State,
  startUrl: string,
  origin: string,
  opts: RequestOptions,
): Promise<Once> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const onAbort = () => controller.abort();
  if (ctx.signal) {
    if (ctx.signal.aborted) controller.abort();
    else ctx.signal.addEventListener('abort', onAbort, { once: true });
  }
  const t0 = ctx.now().getTime();
  let url = startUrl;
  let status = 0;
  let bytes = 0;
  try {
    let sendCredential = true;
    for (let hops = 0; ; hops++) {
      if (st.count >= MAX_REQUESTS_PER_STEP)
        throw new PatternError(`more than ${MAX_REQUESTS_PER_STEP} requests in one step`, 'request-budget');
      st.count++;
      const headers = new Headers({ 'user-agent': ctx.userAgent });
      if (opts.accept) headers.set('accept', opts.accept);
      if (opts.validator) {
        if (opts.validator.startsWith('lm:')) headers.set('if-modified-since', opts.validator.slice(3));
        else headers.set('if-none-match', opts.validator);
      }
      if (opts.range) headers.set('range', `bytes=${opts.range.start}-${opts.range.end}`);
      const secret = opts.auth ? ctx.credentials?.[opts.auth.credential] : undefined;
      if (opts.auth && secret && sendCredential && new URL(url).origin === origin)
        headers.set(opts.auth.header, opts.auth.scheme ? `${opts.auth.scheme} ${secret}` : secret);

      let res: Response;
      try {
        res = await ctx.fetch(url, {
          method: opts.method ?? 'GET',
          headers,
          redirect: 'manual',
          signal: controller.signal,
        });
      } catch (cause) {
        if (timedOut || controller.signal.aborted)
          throw new PatternError('request timed out', 'timeout', { cause });
        throw new PatternError('network error', 'network', { cause });
      }
      status = res.status;

      if (status >= 300 && status < 400 && status !== 304) {
        const loc = res.headers.get('location');
        await res.body?.cancel().catch(() => {});
        if (!loc) throw new PatternError(`redirect without location (${status})`, 'http', { status });
        if (hops >= MAX_REDIRECTS) throw new PatternError('too many redirects', 'http', { status });
        const next = new URL(loc, url);
        if (next.protocol !== 'https:' && next.protocol !== 'http:')
          throw new PatternError('redirect to a non-http URL', 'http', { status });
        if (next.origin !== origin) sendCredential = false;
        url = next.href;
        continue;
      }

      if (isRateLimited(res)) {
        await res.body?.cancel().catch(() => {});
        return { limited: { status, headers: res.headers } };
      }
      if (status === 304) {
        await res.body?.cancel().catch(() => {});
        return {
          url,
          status,
          notModified: true,
          headers: res.headers,
          text: '',
          validator: validatorOf(res.headers) ?? opts.validator ?? null,
          truncated: false,
        };
      }
      if (status < 200 || status >= 300) {
        await res.body?.cancel().catch(() => {});
        if (status === 408 || status >= 500)
          throw new PatternError(`server error (${status})`, 'server', { status });
        throw new PatternError(`unexpected response (${status})`, 'http', { status });
      }

      const maxBytes = opts.maxBytes ?? MAX_BODY_BYTES;
      const rangeLen = opts.range ? opts.range.end - opts.range.start + 1 : undefined;
      // A 200 that ignored the Range is read only to the range length.
      const ignoredRange = rangeLen !== undefined && status === 200;
      const readLimit = ignoredRange ? (rangeLen as number) : maxBytes;
      const declared = Number(res.headers.get('content-length'));
      if (opts.method !== 'HEAD' && !ignoredRange && Number.isFinite(declared) && declared > maxBytes) {
        await res.body?.cancel().catch(() => {});
        throw new PatternError('response too large', 'too-large', { status });
      }
      let text = '';
      let truncated = false;
      if (opts.method !== 'HEAD' && res.body) {
        const read = await readBody(res.body, readLimit, ignoredRange);
        text = read.text;
        bytes = read.bytes;
        truncated = read.truncated;
        if (read.overflow) throw new PatternError('response too large', 'too-large', { status });
      }
      return {
        url,
        status,
        notModified: false,
        headers: res.headers,
        text,
        validator: validatorOf(res.headers),
        truncated,
      };
    }
  } catch (err) {
    if (err instanceof PatternError) throw err;
    if (timedOut || controller.signal.aborted)
      throw new PatternError('request timed out', 'timeout', { cause: err });
    throw new PatternError('network error', 'network', { cause: err });
  } finally {
    clearTimeout(timer);
    ctx.signal?.removeEventListener('abort', onAbort);
    const u = new URL(url);
    ctx.log('http', { origin: u.origin, path: u.pathname, status, bytes, ms: ctx.now().getTime() - t0 });
  }
}

async function readBody(
  body: ReadableStream<Uint8Array>,
  limit: number,
  stopAtLimit: boolean,
): Promise<{ text: string; bytes: number; truncated: boolean; overflow: boolean }> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  let overflow = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (total + value.byteLength > limit) {
      if (stopAtLimit) {
        chunks.push(value.subarray(0, limit - total));
        total = limit;
        truncated = true;
      } else {
        overflow = true;
      }
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return { text: new TextDecoder().decode(all), bytes: total, truncated, overflow };
}
