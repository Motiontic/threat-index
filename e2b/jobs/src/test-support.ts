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

export interface TarSpec {
  path: string;
  data?: string;
  /** '0' file (default), '5' directory, '2' symlink, 'x' pax, 'L' GNU long name. */
  type?: string;
  badChecksum?: boolean;
}

/** A small ustar writer for tests: header blocks, data padded to 512, two zero blocks at the end. */
export function makeTar(entries: TarSpec[], opts: { end?: boolean } = {}): Buffer {
  const blocks: Buffer[] = [];
  const header = (name: string, size: number, type: string, bad: boolean): Buffer => {
    const h = Buffer.alloc(512);
    h.write(name.slice(0, 100), 0, 'utf8');
    h.write('0000644\0', 100);
    h.write('0000000\0', 108);
    h.write('0000000\0', 116);
    h.write(`${size.toString(8).padStart(11, '0')}\0`, 124);
    h.write('00000000000\0', 136);
    h.write('        ', 148);
    h.write(type, 156);
    h.write('ustar\0', 257);
    h.write('00', 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${(bad ? sum + 1 : sum).toString(8).padStart(6, '0')}\0 `, 148);
    return h;
  };
  const body = (data: Buffer) => {
    blocks.push(data, Buffer.alloc((512 - (data.length % 512)) % 512));
  };
  for (const e of entries) {
    const type = e.type ?? '0';
    const data = Buffer.from(e.data ?? '');
    const isFile = type === '0' || type === 'x' || type === 'L';
    blocks.push(header(e.path, isFile ? data.length : 0, type, e.badChecksum ?? false));
    if (isFile) body(data);
  }
  if (opts.end !== false) blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** A pax record `<len> <key>=<value>\n` with its self-describing length. */
export function paxRecord(key: string, value: string): string {
  const rest = ` ${key}=${value}\n`;
  let len = rest.length + 1;
  while (String(len).length + rest.length !== len) len = String(len).length + rest.length;
  return `${len}${rest}`;
}

export const bodyOf = (bytes: Uint8Array): ReadableStream<Uint8Array> =>
  new Response(bytes as BodyInit).body as ReadableStream<Uint8Array>;
