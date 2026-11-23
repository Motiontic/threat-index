/** Test doubles shared by the job tests. Not part of the bundle. */
import { gzipSync } from 'node:zlib';
import type { JobApi, RowTable } from './client.ts';
import type { Job, JobContext } from './types.ts';

export const JOB_ID = '01HZX3K9ABCDEFGHJKMNPQRSTV';

export interface FakeApi extends JobApi {
  store: Map<string, Uint8Array>;
  types: Map<string, string>;
  /** Keys in the order they were written. */
  puts: string[];
  tables: Record<RowTable, Record<string, unknown>[]>;
  completed: unknown[];
}

export function fakeApi(tables: Partial<Record<RowTable, Record<string, unknown>[]>> = {}): FakeApi {
  const store = new Map<string, Uint8Array>();
  const types = new Map<string, string>();
  const puts: string[] = [];
  const all = { vulns: [], advisories: [], signals: [], ...tables } as FakeApi['tables'];
  const enc = new TextEncoder();
  const api: FakeApi = {
    store,
    types,
    puts,
    tables: all,
    completed: [],
    async uploadUrls() {
      throw new Error('not used');
    },
    async upload() {
      throw new Error('not used');
    },
    async complete(r) {
      api.completed.push(r);
    },
    async putObject(key, body, contentType) {
      store.set(key, typeof body === 'string' ? enc.encode(body) : body);
      types.set(key, contentType);
      puts.push(key);
    },
    async getObject(key) {
      return store.get(key) ?? null;
    },
    async *list(prefix) {
      for (const [key, bytes] of [...store].sort(([a], [b]) => a.localeCompare(b)))
        if (key.startsWith(prefix)) yield { key, size: bytes.byteLength };
    },
    async rows(table) {
      return { rows: all[table], next: null };
    },
    async *allRows(table) {
      for (const r of all[table]) yield r;
    },
  };
  return api;
}

export function fakeCtx(api: JobApi): {
  ctx: JobContext;
  logs: { msg: string; extra?: Record<string, unknown> }[];
} {
  const logs: { msg: string; extra?: Record<string, unknown> }[] = [];
  return { ctx: { api, log: (msg, extra) => logs.push({ msg, ...(extra ? { extra } : {}) }) }, logs };
}

export const job = (over: Partial<Job> = {}): Job => ({
  id: JOB_ID,
  kind: 'first-load',
  apiBase: 'https://api.test',
  hmac: 'key',
  ...over,
});

/** A fetch that serves `routes[url]`, and fails the test on any other URL. */
export function fakeFetch(routes: Record<string, () => Response>): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const fn = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    const make = routes[url];
    if (!make) throw new Error(`unexpected fetch: ${url}`);
    return make();
  }) as typeof fetch & { calls: string[] };
  fn.calls = calls;
  return fn;
}

export const gz = (text: string): Uint8Array<ArrayBuffer> => new Uint8Array(gzipSync(text));
export const noSleep = async () => {};
