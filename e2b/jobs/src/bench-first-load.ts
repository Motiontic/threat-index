/**
 * Profiles `first-load` for cisa-kev against a fake API and a fake fetch (no network).
 * Usage: pnpm --filter @ti/e2b-jobs bench:first-load -- [--latency-ms 150] [--records 1500]
 * Every API call waits `--latency-ms` (an assumed E2B-to-Cloudflare signed round trip) and calls overlap
 * when the job makes them in parallel. The real client signs and pages, so ROWS_PAGE and retries count.
 */
import sampleJson from '../../../fixtures/cisa-kev/sample.json';
import { createJobApi } from './client.ts';
import { run } from './jobs/first-load.ts';
import type { Job } from './types.ts';

const arg = (name: string, dflt: number): number => {
  const i = process.argv.indexOf(`--${name}`);
  const n = i >= 0 ? Number(process.argv[i + 1]) : dflt;
  if (!Number.isFinite(n) || n < 0) throw new Error(`bad --${name}`);
  return n;
};
const latencyMs = arg('latency-ms', 150);
const recordCount = arg('records', 1500);

const JOB_ID = '01HZX3K9ABCDEFGHJKMNPQRSTV';
const KEV_URL = 'https://feeds.test/kev.json';
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const sample = sampleJson as { vulnerabilities: Record<string, unknown>[] };
const entry = sample.vulnerabilities[0] as Record<string, unknown>;
const catalog = {
  ...sample,
  vulnerabilities: Array.from({ length: recordCount }, (_, i) => ({
    ...entry,
    cveID: `CVE-2030-${String(1000 + i)}`,
  })),
};

const seeded: Record<string, Record<string, unknown>[]> = {
  vulns: Array.from({ length: 20_000 }, (_, i) => ({ key: `CVE-2019-${String(10_000 + i)}` })),
  advisories: Array.from({ length: 5_000 }, (_, i) => ({ source: 'seed', source_id: `ADV-${i}` })),
  signals: Array.from({ length: 30_000 }, (_, i) => ({
    vuln_key: `CVE-2019-${String(10_000 + (i % 20_000))}`,
    kind: 'seed',
    source: 'seed',
    ref: String(i),
  })),
};

const calls: Record<string, number> = { rows: 0, 'get-object': 0, list: 0, 'put-object': 0 };
let inFlight = 0;
let peak = 0;
const store = new Map<string, Uint8Array>();

const apiFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input));
  const method = init?.method ?? 'GET';
  inFlight++;
  peak = Math.max(peak, inFlight);
  try {
    await sleep(latencyMs);
    const rowsMatch = /\/rows\/(\w+)$/.exec(url.pathname);
    if (rowsMatch) {
      calls.rows = (calls.rows ?? 0) + 1;
      const all = seeded[rowsMatch[1] as string] ?? [];
      const start = Number(url.searchParams.get('after') ?? 0);
      const limit = Number(url.searchParams.get('limit') ?? 500);
      const rows = all.slice(start, start + limit);
      const next = start + limit < all.length ? String(start + limit) : null;
      return Response.json({ rows, next });
    }
    if (url.pathname.endsWith('/list')) {
      calls.list = (calls.list ?? 0) + 1;
      const prefix = url.searchParams.get('prefix') ?? '';
      const objects = [...store]
        .filter(([k]) => k.startsWith(prefix))
        .map(([key, v]) => ({ key, size: v.byteLength }));
      return Response.json({ objects, cursor: null });
    }
    const objMatch = /\/objects\/(.+)$/.exec(url.pathname);
    if (objMatch) {
      const key = objMatch[1] as string;
      if (method === 'PUT') {
        calls['put-object'] = (calls['put-object'] ?? 0) + 1;
        store.set(key, new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer()));
        return new Response(null, { status: 200 });
      }
      calls['get-object'] = (calls['get-object'] ?? 0) + 1;
      const hit = store.get(key);
      return hit ? new Response(hit as BodyInit) : new Response(null, { status: 404 });
    }
    return new Response(null, { status: 400 });
  } finally {
    inFlight--;
  }
}) as typeof fetch;

const api = createJobApi(
  { id: JOB_ID, apiBase: 'https://api.test', hmac: 'bench-key' },
  { fetch: apiFetch, sleep: async () => {} },
);
const sourceFetch = (async (input: RequestInfo | URL) => {
  if (String(input) !== KEV_URL) throw new Error('unexpected fetch');
  return new Response(JSON.stringify(catalog), { headers: { 'content-type': 'application/json' } });
}) as typeof fetch;

const job: Job = {
  id: JOB_ID,
  kind: 'first-load',
  sourceId: 'cisa-kev',
  url: KEV_URL,
  apiBase: 'https://api.test',
  hmac: 'bench-key',
};
const started = performance.now();
await run(
  job,
  { api, log: () => {} },
  {
    fetch: sourceFetch,
    sleep: async () => {},
    duckdb: () => null,
    now: () => new Date('2026-11-23T10:00:00Z'),
  },
);
const wallS = (performance.now() - started) / 1000;
console.log(
  JSON.stringify(
    {
      source: 'cisa-kev',
      records: recordCount,
      latencyMs,
      seeded: { vulns: 20_000, advisories: 5_000, signals: 30_000 },
      wallSeconds: Number(wallS.toFixed(1)),
      callsPerRoute: calls,
      peakInFlight: peak,
    },
    null,
    2,
  ),
);
