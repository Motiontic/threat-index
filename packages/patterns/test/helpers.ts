import type { Cursor } from '@ti/core/types';
import type { SourceConfig } from '@ti/sources/registry';
import type { PatternContext } from '../src/types';

export interface Recorded {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export interface Route {
  method?: string;
  /** An exact URL, or a pattern for the whole URL (query included). */
  url: string | RegExp;
  /** Builds a fresh Response each call. */
  respond: (req: Recorded, signal: AbortSignal | null | undefined) => Response | Promise<Response>;
}

export const NOW = new Date('2025-05-21T12:00:00.000Z');

export function reply(
  body: string | null,
  status = 200,
  headers: Record<string, string> = {},
): Route['respond'] {
  return () => new Response(body, { status, headers });
}

export function route(url: string | RegExp, respond: Route['respond'], method = 'GET'): Route {
  return { method, url, respond };
}

export interface Harness {
  ctx: PatternContext;
  requests: Recorded[];
  waits: number[];
  logs: Array<{ msg: string; extra?: Record<string, unknown> | undefined }>;
}

/** A context whose `fetch` serves `routes` and fails on any request they do not cover. */
export function makeCtx(opts: {
  source: SourceConfig;
  routes?: Route[];
  cursor?: Cursor | null;
  now?: Date;
  userAgent?: string;
  credentials?: PatternContext['credentials'];
  runId?: string;
}): Harness {
  const requests: Recorded[] = [];
  const waits: number[] = [];
  const logs: Harness['logs'] = [];
  const routes = opts.routes ?? [];
  const fake = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => {
      headers[k] = v;
    });
    const rec = { method, url, headers };
    requests.push(rec);
    const hit = routes.find(
      (r) =>
        (r.method ?? 'GET').toUpperCase() === method &&
        (typeof r.url === 'string' ? r.url === url : r.url.test(url)),
    );
    if (!hit) throw new Error(`unexpected request: ${method} ${url}`);
    return hit.respond(rec, init?.signal);
  };
  const ctx: PatternContext = {
    source: opts.source,
    cursor: opts.cursor ?? null,
    userAgent: opts.userAgent ?? 'threat-index-test/1.0 (ops@example.test)',
    fetch: fake as typeof fetch,
    wait: async (ms) => {
      waits.push(ms);
    },
    log: (msg, extra) => {
      logs.push({ msg, extra });
    },
    now: () => opts.now ?? NOW,
    ...(opts.credentials ? { credentials: opts.credentials } : {}),
    ...(opts.runId ? { runId: opts.runId } : {}),
  };
  return { ctx, requests, waits, logs };
}

/** Serves `text` and honours `Range: bytes=a-b` with a 206. */
export function ranged(text: string, headers: Record<string, string> = {}): Route['respond'] {
  return (req) => {
    const bytes = new TextEncoder().encode(text);
    const m = /bytes=(\d+)-(\d+)/.exec(req.headers.range ?? '');
    if (!m) return new Response(bytes, { status: 200, headers });
    const start = Number(m[1]);
    if (start >= bytes.length) return new Response('', { status: 416 });
    const end = Math.min(Number(m[2]), bytes.length - 1);
    return new Response(bytes.slice(start, end + 1), {
      status: 206,
      headers: { ...headers, 'content-range': `bytes ${start}-${end}/${bytes.length}` },
    });
  };
}

export const SHA_A = 'a'.repeat(40);
export const SHA_B = 'b'.repeat(40);
