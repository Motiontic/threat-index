import type { Env } from '../../src/env';

export interface Seen {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  signal: AbortSignal;
  aborted: boolean;
}
export type Handler = (req: Request, seen: Seen) => Response | Promise<Response>;

export interface FakeApi {
  fetcher: Fetcher;
  calls: Seen[];
}

/** A stand-in for the `API` service binding. The handler waits on `req.signal` if a test wants to see an abort. */
export function fakeApi(handler: Handler): FakeApi {
  const calls: Seen[] = [];
  const fetcher = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      const headers: Record<string, string> = {};
      for (const [k, v] of req.headers) headers[k] = v;
      const seen: Seen = {
        method: req.method,
        path: url.pathname + url.search,
        headers,
        body: await req.clone().text(),
        signal: req.signal,
        aborted: false,
      };
      req.signal.addEventListener('abort', () => {
        seen.aborted = true;
      });
      calls.push(seen);
      return handler(req, seen);
    },
  } as unknown as Fetcher;
  return { fetcher, calls };
}

export const withApi = (env: Env, api: FakeApi, extra: Partial<Env> = {}): Env => ({ ...env, API: api.fetcher, ...extra });
export const ok = (body: unknown) => Response.json(body);
export const status = (code: number, body: unknown = { error: 'x' }, headers: Record<string, string> = {}) =>
  Response.json(body, { status: code, headers });
