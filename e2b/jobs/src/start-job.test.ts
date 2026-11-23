import { deriveJobKey, SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyRequest } from '@ti/core/sign';
import { describe, expect, it } from 'vitest';
import { parseArgs, startJob } from './start-job.ts';

const SECRET = 'ops-secret';

describe('start-job', () => {
  it('parses flags and rejects bad ones', () => {
    expect(
      parseArgs([
        '--',
        '--api',
        'https://a.test',
        '--kind',
        'first-load',
        '--source',
        'cisa-kev',
        '--no-wait',
      ]),
    ).toEqual({
      api: 'https://a.test',
      kind: 'first-load',
      source: 'cisa-kev',
      wait: false,
    });
    expect(parseArgs(['--kind', 'first-load'])).toMatch(/--api/);
    expect(parseArgs(['--api', 'x', '--kind', 'nope'])).toMatch(/--kind/);
    expect(parseArgs(['--api', 'x', '--kind', 'echo', '--wat'])).toMatch(/unknown/);
  });

  it('sends a signed start request, polls, and prints the id and status only', async () => {
    const seen: { method: string; path: string; headers: Headers; body: string }[] = [];
    let polls = 0;
    const fetchFn = (async (url: string, init?: RequestInit) => {
      const req = new Request(url, init);
      const body = await req.text();
      seen.push({ method: req.method, path: new URL(url).pathname, headers: req.headers, body });
      if (req.method === 'POST') return Response.json({ jobId: 'JOBID', status: 'running' }, { status: 201 });
      return Response.json({ status: ++polls < 2 ? 'running' : 'complete' });
    }) as typeof fetch;
    const out: string[] = [];
    const code = await startJob(
      { api: 'https://api.test/', kind: 'nightly-fold', day: '2026-11-22', wait: true },
      SECRET,
      { fetch: fetchFn, sleep: async () => {}, print: (l) => out.push(l) },
    );
    expect(code).toBe(0);
    expect(out).toEqual(['job JOBID complete']);
    const start = seen[0];
    expect(start?.path).toBe('/internal/jobs');
    expect(JSON.parse(start?.body ?? '{}')).toMatchObject({ kind: 'nightly-fold', day: '2026-11-22' });
    expect(JSON.parse(start?.body ?? '{}').requestId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(
      await verifyRequest(SECRET, {
        method: 'POST',
        path: start?.path ?? '',
        timestamp: start?.headers.get(TIMESTAMP_HEADER) ?? null,
        signature: start?.headers.get(SIGNATURE_HEADER) ?? null,
        body: start?.body ?? '',
      }),
    ).toBe(true);
    // The ops key, not a job key.
    expect(await deriveJobKey(SECRET, 'JOBID')).not.toBe(SECRET);
  });

  it('exits non-zero when the job fails or the start is refused, and with --no-wait prints the start status', async () => {
    const mk = (startStatus: number, jobStatus: string) =>
      (async (_u: string, init?: RequestInit) =>
        init?.method === 'POST'
          ? Response.json({ jobId: 'J', status: 'running' }, { status: startStatus })
          : Response.json({ status: jobStatus })) as unknown as typeof fetch;
    const base = { fetch: mk(201, 'failed'), sleep: async () => {}, print: () => {} };
    expect(await startJob({ api: 'https://a.test', kind: 'echo', wait: true }, SECRET, base)).toBe(1);
    expect(
      await startJob({ api: 'https://a.test', kind: 'echo', wait: true }, SECRET, {
        ...base,
        fetch: mk(400, ''),
      }),
    ).toBe(1);
    const out: string[] = [];
    expect(
      await startJob({ api: 'https://a.test', kind: 'echo', wait: false }, SECRET, {
        ...base,
        print: (l) => out.push(l),
      }),
    ).toBe(0);
    expect(out).toEqual(['job J running']);
  });
});
