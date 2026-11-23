import type { JobRequest } from '@ti/core/control';
import { SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyRequest } from '@ti/core/sign';
import { beforeEach, describe, expect, it } from 'vitest';
import { PermanentError } from '../src/errors';
import { startHeavyJob } from '../src/heavy';
import { runStep } from '../src/step';
import { E, getRun, mkDeps, msgBody, NOW, reset, result } from './helpers';

const SECRET = 'test-secret';
const req: JobRequest = {
  requestId: 'r-0',
  kind: 'big-file',
  sourceId: 'cve-list',
  reason: 'big',
  url: 'https://example.com/f',
};

function fakeApi(status: number, body: unknown = { jobId: 'job-1' }) {
  const seen: { url: string; method: string; headers: Headers; body: string }[] = [];
  const API = {
    fetch: async (url: string, init: RequestInit) => {
      seen.push({
        url,
        method: init.method as string,
        headers: new Headers(init.headers),
        body: init.body as string,
      });
      return new Response(JSON.stringify(body), { status });
    },
  } as unknown as Fetcher;
  return { API, seen };
}

beforeEach(reset);

describe('startHeavyJob', () => {
  it('sends a signed request that verifies, and fails with a changed body', async () => {
    const { API, seen } = fakeApi(201);
    expect(await startHeavyJob({ API, JOB_HMAC_SECRET: SECRET }, req, NOW)).toEqual({ jobId: 'job-1' });
    const r = seen[0];
    expect(r?.url).toBe('https://ti-api.internal/internal/jobs');
    expect(r?.method).toBe('POST');
    expect(r?.headers.get('content-type')).toBe('application/json');
    const input = {
      method: 'POST',
      path: '/internal/jobs',
      timestamp: r?.headers.get(TIMESTAMP_HEADER) ?? null,
      signature: r?.headers.get(SIGNATURE_HEADER) ?? null,
    };
    expect(input.timestamp).toBe(String(Math.floor(NOW.getTime() / 1000)));
    expect(await verifyRequest(SECRET, { ...input, body: r?.body as string }, NOW)).toBe(true);
    expect(await verifyRequest(SECRET, { ...input, body: `${r?.body}x` }, NOW)).toBe(false);
    expect(await verifyRequest('other', { ...input, body: r?.body as string }, NOW)).toBe(false);
  });

  it('200 with existing:true is success', async () => {
    const { API } = fakeApi(200, { jobId: 'j', existing: true });
    expect(await startHeavyJob({ API, JOB_HMAC_SECRET: SECRET }, req, NOW)).toEqual({ jobId: 'j' });
  });

  it('429, 502, 503 and 500 are retryable', async () => {
    for (const status of [429, 502, 503, 500]) {
      const { API } = fakeApi(status);
      const err = await startHeavyJob({ API, JOB_HMAC_SECRET: SECRET }, req, NOW).catch((e) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(PermanentError);
      expect(err.message).toBe(`ti-api returned ${status}`);
    }
  });

  it('501 and other 4xx are permanent and carry only the error code', async () => {
    for (const [status, code] of [
      [501, 'job_kind_not_ready'],
      [400, 'bad_request'],
      [401, 'unauthorized'],
    ] as const) {
      const { API } = fakeApi(status, { error: code, detail: 'LEAK-SECRET' });
      const err = await startHeavyJob({ API, JOB_HMAC_SECRET: SECRET }, req, NOW).catch((e) => e);
      expect(err).toBeInstanceOf(PermanentError);
      expect(err.message).toBe(`ti-api returned ${status} ${code}`);
    }
  });

  it('no secret or no binding is permanent and sends nothing', async () => {
    const { API, seen } = fakeApi(201);
    await expect(startHeavyJob({ API }, req, NOW)).rejects.toBeInstanceOf(PermanentError);
    await expect(startHeavyJob({ JOB_HMAC_SECRET: SECRET }, req, NOW)).rejects.toBeInstanceOf(PermanentError);
    expect(seen).toHaveLength(0);
  });

  it('through a step: 500 retries, a missing secret fails the run', async () => {
    const heavy = { kind: 'big-file' as const, sourceId: 'cve-list', reason: 'big' };
    const patternFor = () => ({
      check: async () => 'changed' as const,
      fetch: async () => result({ heavy }),
    });

    const api500 = fakeApi(500);
    const b1 = msgBody('cve-list');
    const retry = await runStep(
      b1,
      1,
      E,
      mkDeps({
        patternFor,
        startJob: (r) => startHeavyJob({ API: api500.API, JOB_HMAC_SECRET: SECRET }, r, NOW),
      }),
    );
    expect(retry.ack).toBe(false);
    expect((await getRun(b1.runId))?.status).toBe('running');

    const b2 = msgBody('cve-list');
    const failed = await runStep(
      b2,
      1,
      E,
      mkDeps({ patternFor, startJob: (r) => startHeavyJob({ API: api500.API }, r, NOW) }),
    );
    expect(failed).toEqual({ ack: true, status: 'failed' });
    expect((await getRun(b2.runId))?.status).toBe('failed');
  });
});
