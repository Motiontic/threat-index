/**
 * Runs the whole search-index job over a synthetic hot set against a fake API that counts what is written and
 * keeps nothing, then prints one JSON line: peak heap, total bytes, object count. The scale test spawns it with
 * a capped heap:  node --max-old-space-size=1536 --experimental-strip-types search-index.heap-run.ts [entries] [summaryWords]
 * Not part of the bundle.
 */
import { getHeapStatistics } from 'node:v8';
import type { JobApi } from '../client.ts';
import { synthetic } from './search-index.synth.ts';
import { run } from './search-index.ts';

const entries = Number(process.argv[2] ?? 250_000);
const summaryWords = Number(process.argv[3] ?? 0);
const all = synthetic(entries, summaryWords);
let peak = 0;
const sample = () => {
  peak = Math.max(peak, getHeapStatistics().used_heap_size);
};
const timer = setInterval(sample, 10);

let objects = 0;
let bytes = 0;
let largest = 0;
const enc = new TextEncoder();
const api = {
  async putObject(_key: string, body: string | Uint8Array) {
    sample();
    const n = typeof body === 'string' ? enc.encode(body).length : body.length;
    objects++;
    bytes += n;
    largest = Math.max(largest, n);
    await new Promise((r) => setImmediate(r)); // let uploads overlap like real ones
  },
  async deleteObject() {},
  async *list() {},
  async rows(table: string, opts: { after?: string; limit?: number } = {}) {
    if (table !== 'vulns') return { rows: [], next: null };
    const start = opts.after ? Number(opts.after) : 0;
    const end = Math.min(all.length, start + (opts.limit ?? 1000));
    return { rows: all.slice(start, end), next: end >= all.length ? null : String(end) };
  },
} as unknown as JobApi;

const lines: string[] = [];
await run(
  { id: 'heap-run', kind: 'search-index', apiBase: 'https://x', hmac: 'x' },
  {
    api,
    log: (msg, extra) => lines.push(JSON.stringify({ msg, ...extra })),
  },
);
sample();
clearInterval(timer);
console.log(
  JSON.stringify({
    entries,
    summaryWords,
    peakHeapMB: Math.round(peak / 2 ** 20),
    heapLimitMB: Math.round(getHeapStatistics().heap_size_limit / 2 ** 20),
    objects,
    totalBytes: bytes,
    largestObjectBytes: largest,
    log: lines.map((l) => JSON.parse(l)),
  }),
);
