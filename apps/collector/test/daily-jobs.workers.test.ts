import { SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyRequest } from '@ti/core/sign';
import { beforeEach, describe, expect, it } from 'vitest';
import { DAILY_JOBS, dailyJobId, startDailyJobs } from '../src/daily-jobs';
import type { startHeavyJob } from '../src/heavy';
import worker from '../src/index';
import { E, NOW, reset } from './helpers';

// ti-api's JOB_ID (apps/api/src/routes/internal-jobs.ts)
const JOB_ID = /^[0-9A-HJKMNP-TV-Z]{26}(-[0-9]{1,5})?$/;
const AT = new Date('2026-11-24T02:30:00.000Z');
const SECRET = 'test-job-hmac-secret';

interface Sent {
  body: Record<string, unknown>;
  raw: string;
  headers: Headers;
}
function stubApi(failFirst = false) {
  const sent: Sent[] = [];
  let n = 0;
  const API = {
    fetch: async (_url: string, init: RequestInit) => {
      n++;
      sent.push({
        body: JSON.parse(init.body as string),
        raw: init.body as string,
        headers: new Headers(init.headers),
      });
      if (failFirst && n === 1) return new Response('{}', { status: 500 });
      return new Response(
        JSON.stringify({ jobId: (JSON.parse(init.body as string) as { requestId: string }).requestId }),
        {
          status: 201,
        },
      );
    },
  } as unknown as Fetcher;
  return { API, sent };
}
const scheduled = (cron: string, at: Date) => ({ cron, scheduledTime: at.getTime() }) as ScheduledController;
const quiet = async <T>(fn: () => Promise<T>): Promise<{ out: T; logs: Record<string, unknown>[] }> => {
  const logs: Record<string, unknown>[] = [];
  const orig = console.log;
  console.log = (m: unknown) => {
    try {
      logs.push(JSON.parse(String(m)));
    } catch {
      // not ours
    }
  };
  try {
    return { out: await fn(), logs };
  } finally {
    console.log = orig;
  }
};

beforeEach(reset);

describe('dailyJobId', () => {
  it('matches ti-api JOB_ID, is stable per kind and day, and differs across both', async () => {
    const a = await dailyJobId('nightly-fold', '2026-11-23');
    expect(a).toMatch(JOB_ID);
    expect(a).toHaveLength(26);
    expect(await dailyJobId('nightly-fold', '2026-11-23')).toBe(a);
    expect(await dailyJobId('search-index', '2026-11-23')).not.toBe(a);
    expect(await dailyJobId('nightly-fold', '2026-11-24')).not.toBe(a);
    // The time part is UTC midnight of the day: ids sort by day.
    expect((await dailyJobId('epss-diff', '2026-11-24')).slice(0, 10) > a.slice(0, 10)).toBe(true);
    await expect(dailyJobId('epss-diff', 'nope')).rejects.toThrow();
  });
});

describe('scheduled crons start the daily jobs', () => {
  it('02:30 sends two signed requests; nightly-fold works on yesterday', async () => {
    const { API, sent } = stubApi();
    const { logs } = await quiet(() => worker.scheduled(scheduled('30 2 * * *', AT), { ...E, API } as never));
    expect(sent.map((s) => s.body.kind)).toEqual(['nightly-fold', 'search-index']);
    expect(sent[0]?.body).toEqual({
      kind: 'nightly-fold',
      reason: 'nightly',
      requestId: await dailyJobId('nightly-fold', '2026-11-23'),
      day: '2026-11-23',
    });
    expect(sent[1]?.body).toEqual({
      kind: 'search-index',
      reason: 'nightly',
      requestId: await dailyJobId('search-index', '2026-11-24'),
    });
    for (const s of sent) {
      expect(s.body.requestId).toMatch(JOB_ID);
      const ts = s.headers.get(TIMESTAMP_HEADER) as string;
      const input = {
        method: 'POST',
        path: '/internal/jobs',
        timestamp: ts,
        signature: s.headers.get(SIGNATURE_HEADER),
      };
      expect(await verifyRequest(SECRET, { ...input, body: s.raw }, new Date(Number(ts) * 1000))).toBe(true);
    }
    expect(logs.filter((l) => l.msg === 'daily job started').map((l) => l.kind)).toEqual([
      'nightly-fold',
      'search-index',
    ]);
  });

  it('14:45 sends one epss-diff for the epss source (and the watchdog still runs)', async () => {
    const { API, sent } = stubApi();
    const { logs } = await quiet(() =>
      worker.scheduled(scheduled('45 14 * * *', NOW), { ...E, API } as never),
    );
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toEqual({
      kind: 'epss-diff',
      sourceId: 'epss',
      reason: 'daily',
      requestId: await dailyJobId('epss-diff', '2026-11-23'),
    });
    expect(logs.some((l) => l.msg === 'watchdog report' || String(l.msg).includes('email skipped'))).toBe(
      true,
    );
  });

  it('the same cron twice sends the same ids; the day comes from scheduledTime', async () => {
    const { API, sent } = stubApi();
    await quiet(() => worker.scheduled(scheduled('30 2 * * *', AT), { ...E, API } as never));
    await quiet(() =>
      worker.scheduled(scheduled('30 2 * * *', new Date(AT.getTime() + 3_600_000)), { ...E, API } as never),
    );
    expect(sent).toHaveLength(4);
    expect(sent.slice(0, 2).map((s) => s.body.requestId)).toEqual(sent.slice(2).map((s) => s.body.requestId));
    // A later day gets new ids.
    await quiet(() =>
      worker.scheduled(scheduled('30 2 * * *', new Date(AT.getTime() + 86_400_000)), { ...E, API } as never),
    );
    expect(sent[4]?.body.requestId).not.toBe(sent[0]?.body.requestId);
  });

  it('a failing first start still sends the second, then the cron fails', async () => {
    const { API, sent } = stubApi(true);
    const { logs, out } = await quiet(() =>
      worker.scheduled(scheduled('30 2 * * *', AT), { ...E, API } as never).then(
        () => 'ok',
        (e: Error) => e.message,
      ),
    );
    expect(sent).toHaveLength(2);
    expect(out).toContain('500');
    expect(logs.some((l) => l.msg === 'daily job failed to start' && l.kind === 'nightly-fold')).toBe(true);
  });

  it('KV ingest:false skips EPSS', async () => {
    await E.SETTINGS.put('source:epss', JSON.stringify({ ingest: false }));
    const { API, sent } = stubApi();
    const { logs } = await quiet(() =>
      worker.scheduled(scheduled('45 14 * * *', NOW), { ...E, API } as never),
    );
    expect(sent).toHaveLength(0);
    expect(logs.some((l) => l.msg === 'daily job skipped' && l.kind === 'epss-diff')).toBe(true);
  });

  it('other crons start nothing', async () => {
    const { API, sent } = stubApi();
    for (const cron of ['0 */3 * * *', '0 5 * * 1']) {
      await quiet(() => worker.scheduled(scheduled(cron, NOW), { ...E, API } as never).catch(() => {}));
    }
    expect(sent.filter((s) => s.body.kind === 'nightly-fold' || s.body.kind === 'search-index')).toEqual([]);
    expect(sent.filter((s) => s.body.reason === 'daily')).toEqual([]);
    expect(Object.keys(DAILY_JOBS).sort()).toEqual(['30 2 * * *', '45 14 * * *']);
  });
});

describe('startDailyJobs', () => {
  it('uses the injected start and clock', async () => {
    const calls: unknown[] = [];
    await startDailyJobs('30 2 * * *', AT, E, {
      startJob: (async (_e: unknown, req: unknown, now: Date) => {
        calls.push([req, now.toISOString()]);
        return {};
      }) as typeof startHeavyJob,
      log: () => {},
      now: () => NOW,
    });
    expect(calls).toHaveLength(2);
    expect((calls[0] as [unknown, string])[1]).toBe(NOW.toISOString());
  });
});
