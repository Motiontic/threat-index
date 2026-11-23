import { deriveJobKey, SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyRequest } from '@ti/core/sign';
import { describe, expect, it } from 'vitest';
import { createJobApi } from './client.ts';
import { run as echo } from './jobs/echo.ts';
import { roundTrip } from './round-trip.ts';
import { main, parseJob } from './run.ts';
import type { Job } from './types.ts';

const SECRET = 'ops-secret';
const ID = '01HZX3K9ABCDEFGHJKMNPQRSTV';
const noSleep = async () => {};

async function mkJob(kind: Job['kind'] = 'echo'): Promise<Job> {
  return { id: ID, kind, apiBase: 'https://api.test', hmac: await deriveJobKey(SECRET, ID) };
}

interface Seen {
  url: string;
  method: string;
  body: string;
  headers: Headers;
}
/** A fake API: records calls, answers `upload-urls` with fake URLs, and PUTs with 200. */
function fakeApi(handler?: (n: number, seen: Seen) => Response | undefined) {
  const seen: Seen[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as string, init);
    const s = { url: req.url, method: req.method, body: await req.text(), headers: req.headers };
    seen.push(s);
    const custom = handler?.(seen.length, s);
    if (custom) return custom;
    if (s.url.endsWith('/upload-urls')) {
      const keys = (JSON.parse(s.body) as { keys: string[] }).keys;
      return Response.json({
        urls: keys.map((key) => ({ key, url: `https://r2.test/${key}?sig=SECRETSIG` })),
      });
    }
    return s.method === 'PUT' ? new Response(null, { status: 200 }) : Response.json({ ok: true });
  }) as typeof fetch;
  return { seen, fetchFn };
}

describe('createJobApi', () => {
  it('signs every call so the API can verify it with the derived job key', async () => {
    const { seen, fetchFn } = fakeApi();
    const api = createJobApi(await mkJob(), { fetch: fetchFn, now: () => Date.now(), sleep: noSleep });
    await api.complete({ ok: true });
    const s = seen[0] as Seen;
    expect(new URL(s.url).pathname).toBe(`/internal/jobs/${ID}/complete`);
    const ok = await verifyRequest(await deriveJobKey(SECRET, ID), {
      method: s.method,
      path: new URL(s.url).pathname,
      timestamp: s.headers.get(TIMESTAMP_HEADER),
      signature: s.headers.get(SIGNATURE_HEADER),
      body: s.body,
    });
    expect(ok).toBe(true);
  });
  it('retries a 503 and a network error with a fresh timestamp each time, then succeeds', async () => {
    let t = 1_000_000_000_000;
    const { seen, fetchFn } = fakeApi((n) => {
      if (n === 1) return new Response('no', { status: 503 });
      if (n === 2) throw new TypeError('network');
      return undefined;
    });
    const api = createJobApi(await mkJob(), { fetch: fetchFn, now: () => (t += 5000), sleep: noSleep });
    await api.complete({ ok: true });
    expect(seen).toHaveLength(3);
    const stamps = seen.map((s) => s.headers.get(TIMESTAMP_HEADER));
    expect(new Set(stamps).size).toBe(3);
  });
  it('gives up after 3 retries on persistent 5xx', async () => {
    const { seen, fetchFn } = fakeApi(() => new Response('no', { status: 503 }));
    const api = createJobApi(await mkJob(), { fetch: fetchFn, sleep: noSleep });
    await expect(api.complete({ ok: true })).rejects.toThrow(/failed after retries/);
    expect(seen).toHaveLength(4);
  });
  it('never retries a 4xx', async () => {
    const { seen, fetchFn } = fakeApi(() => new Response('no', { status: 401 }));
    const api = createJobApi(await mkJob(), { fetch: fetchFn, sleep: noSleep });
    await expect(api.complete({ ok: true })).rejects.toThrow(/status 401/);
    expect(seen).toHaveLength(1);
  });
  it('asks for URLs 50 at a time', async () => {
    const { seen, fetchFn } = fakeApi();
    const api = createJobApi(await mkJob(), { fetch: fetchFn, sleep: noSleep });
    const files = Array.from({ length: 120 }, (_, i) => ({
      key: `jobs/${ID}/${i}`,
      body: 'x',
      contentType: 'text/plain',
    }));
    await api.upload(files);
    const asks = seen
      .filter((s) => s.url.endsWith('/upload-urls'))
      .map((s) => JSON.parse(s.body).keys.length);
    expect(asks).toEqual([50, 50, 20]);
    expect(seen.filter((s) => s.method === 'PUT')).toHaveLength(120);
  });
  it('throws on a non-2xx PUT or a missing key, without the URL in the message', async () => {
    const put500 = fakeApi((_n, s) => (s.method === 'PUT' ? new Response('x', { status: 500 }) : undefined));
    const f = [{ key: `jobs/${ID}/a`, body: 'x', contentType: 'text/plain' }];
    const err = await createJobApi(await mkJob(), { fetch: put500.fetchFn, sleep: noSleep })
      .upload(f)
      .catch((e: Error) => e);
    expect((err as Error).message).toMatch(/status 500/);
    expect((err as Error).message).not.toContain('SECRETSIG');
    const missing = fakeApi((_n, s) =>
      s.url.endsWith('/upload-urls') ? Response.json({ urls: [] }) : undefined,
    );
    await expect(
      createJobApi(await mkJob(), { fetch: missing.fetchFn, sleep: noSleep }).upload(f),
    ).rejects.toThrow(/missing a key/);
  });
});

describe('echo and main', () => {
  it('echo uploads echo.json and an empty manifest, and logs no hmac', async () => {
    const { seen, fetchFn } = fakeApi();
    const job = await mkJob();
    const logs: string[] = [];
    const code = await main(job, { client: { fetch: fetchFn, sleep: noSleep }, log: (l) => logs.push(l) });
    expect(code).toBe(0);
    const puts = seen.filter((s) => s.method === 'PUT');
    expect(puts.map((p) => new URL(p.url).pathname)).toEqual([
      `/jobs/${ID}/echo.json`,
      `/inbox/${ID}/manifest.json`,
    ]);
    expect(JSON.parse((puts[0] as Seen).body)).toMatchObject({ id: ID, kind: 'echo', node: process.version });
    expect(JSON.parse((puts[1] as Seen).body)).toMatchObject({ jobId: ID, chunks: [] });
    const last = seen[seen.length - 1] as Seen;
    expect(JSON.parse(last.body)).toEqual({ ok: true });
    expect(logs.join('\n')).not.toContain(job.hmac);
  });
  it('a stub job reports ok:false and exits 1', async () => {
    const { seen, fetchFn } = fakeApi();
    const code = await main(await mkJob('first-load'), {
      client: { fetch: fetchFn, sleep: noSleep },
      log: () => {},
    });
    expect(code).toBe(1);
    const body = JSON.parse((seen[seen.length - 1] as Seen).body);
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/first-load/);
  });
  it('exports echo as a job', () => expect(typeof echo).toBe('function'));
});

describe('parseJob', () => {
  it.each([
    [undefined, /no job description/],
    ['{', /not valid JSON/],
    ['{}', /no id/],
    ['{"id":"a","kind":"nope"}', /unknown job kind/],
    ['{"id":"a","kind":"echo"}', /no apiBase/],
    ['{"id":"a","kind":"echo","apiBase":"https://x"}', /no hmac/],
  ])('rejects %s', (text, re) => {
    expect(() => parseJob(text)).toThrow(re);
  });
});

describe('roundTrip', () => {
  const api = (statuses: string[]) => {
    let polls = 0;
    const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input as string, init);
      const path = new URL(req.url).pathname;
      const ok = await verifyRequest(SECRET, {
        method: req.method,
        path,
        timestamp: req.headers.get(TIMESTAMP_HEADER),
        signature: req.headers.get(SIGNATURE_HEADER),
        body: await req.text(),
      });
      if (!ok) return new Response('{}', { status: 401 });
      if (req.method === 'POST') return Response.json({ jobId: ID, status: 'running' }, { status: 201 });
      return Response.json({ status: statuses[Math.min(polls++, statuses.length - 1)] });
    }) as typeof fetch;
    return { fetchFn, polls: () => polls };
  };
  it('stops on complete with exit 0, printing only id and status', async () => {
    const a = api(['running', 'running', 'complete']);
    const out: string[] = [];
    const code = await roundTrip('https://api.test', SECRET, {
      fetch: a.fetchFn,
      sleep: noSleep,
      print: (l) => out.push(l),
    });
    expect(code).toBe(0);
    expect(a.polls()).toBe(3);
    expect(out).toEqual([`job ${ID} complete`]);
  });
  it('stops on failed with exit 1', async () => {
    const code = await roundTrip('https://api.test', SECRET, {
      fetch: api(['failed']).fetchFn,
      sleep: noSleep,
      print: () => {},
    });
    expect(code).toBe(1);
  });
  it('gives up after the deadline', async () => {
    let t = 0;
    const code = await roundTrip('https://api.test', SECRET, {
      fetch: api(['running']).fetchFn,
      now: () => t,
      sleep: async (ms) => {
        t += ms;
      },
      print: () => {},
      maxMs: 20_000,
    });
    expect(code).toBe(1);
  });
});
