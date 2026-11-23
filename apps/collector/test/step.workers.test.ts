import { NotImplementedError } from '@ti/core/errors';
import { rawReceiptKey } from '@ti/core/r2-keys';
import type { PatternContext } from '@ti/patterns/types';
import { decodeTime } from 'ulid';
import { beforeEach, describe, expect, it } from 'vitest';
import { runStep } from '../src/step';
import {
  cursor,
  E,
  fakeJobs,
  getCursor,
  getRun,
  gunzipText,
  mkDeps,
  msgBody,
  NOW,
  newRunId,
  reset,
  result,
  seedCursor,
  seedRun,
} from './helpers';

beforeEach(reset);

const kevRecord = { key: 'CVE-2024-1' } as never;

describe('runStep', () => {
  it('unchanged: finishes the run without fetching', async () => {
    let fetched = false;
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'unchanged',
        fetch: async () => {
          fetched = true;
          return result();
        },
      }),
    });
    const body = msgBody('cve-list');
    const out = await runStep(body, 1, E, deps);
    expect(out).toEqual({ ack: true, status: 'unchanged' });
    expect(fetched).toBe(false);
    expect((await getRun(body.runId))?.status).toBe('unchanged');
  });

  it('happy path: receipt in R2 before parsing, steady writes, cursor committed, run ok with counts', async () => {
    const body = msgBody('cisa-kev');
    const key = rawReceiptKey('cisa-kev', body.runId, 0, new Date(decodeTime(body.runId)));
    let receiptThereAtParse = false;
    let priority: string | undefined;
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () =>
          result({
            items: [
              { id: 'a', body: 1 },
              { id: 'b', body: 2 },
            ],
          }),
      }),
      loadParser: async () => {
        receiptThereAtParse = (await E.BUCKET.head(key)) !== null; // the parser is loaded, then runs
        return { parse: () => [kevRecord] };
      },
      link: async () => {
        return {
          rows: [{ table: 'vulns', op: 'upsert', row: { key: 'x' } }],
          docs: ['CVE-2024-1'],
          skipped: 0,
        };
      },
      writeRows: async (_dbs, rows, opts) => {
        priority = opts.priority;
        return { written: rows.length * 3, statements: 1, deferred: false };
      },
    });
    const out = await runStep(body, 1, E, deps);
    expect(out).toEqual({ ack: true, status: 'ok' });
    expect(receiptThereAtParse).toBe(true);
    expect(priority).toBe('steady');
    expect(await getCursor('cisa-kev')).toEqual({ kind: 'timestamp', value: 't1', etag: null });
    const run = await getRun(body.runId);
    expect(run).toMatchObject({ status: 'ok', found: 2, written: 3, error: null });
    expect(run?.bytes).toBeGreaterThan(0);
    expect(run?.finished_at).not.toBeNull();
    const text = await gunzipText((await E.BUCKET.get(key)) as R2ObjectBody);
    expect(text.split('\n')[0]).toContain('"type":"receipt"');
    expect(deps.logs.join('\n')).toContain('"docs":1');
  });

  it('more: queues step 1 with the next cursor; step 1 writes a -1 receipt and finishes the run', async () => {
    const jobs = fakeJobs();
    const env = { ...E, JOBS: jobs.queue };
    const c1 = cursor('t1');
    const first = msgBody('cisa-kev');
    let page = 0;
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () =>
          page++ === 0 ? result({ nextCursor: c1, more: true }) : result({ nextCursor: cursor('t2') }),
      }),
      loadParser: async () => ({ parse: () => [kevRecord] }),
    });
    expect(await runStep(first, 1, env, deps)).toEqual({ ack: true, status: 'ok' });
    expect(jobs.sent).toEqual([{ sourceId: 'cisa-kev', runId: first.runId, step: 1, from: c1 }]);
    expect((await getRun(first.runId))?.status).toBe('running');
    expect(await getCursor('cisa-kev')).toMatchObject({ value: 't1' });

    expect(await runStep(jobs.sent[0], 1, env, deps)).toEqual({ ack: true, status: 'ok' });
    const day = new Date(decodeTime(first.runId));
    expect(await E.BUCKET.head(rawReceiptKey('cisa-kev', first.runId, 1, day))).not.toBeNull();
    expect(await getRun(first.runId)).toMatchObject({ status: 'ok', found: 2 });
    expect(await getCursor('cisa-kev')).toMatchObject({ value: 't2' });
  });

  it('a failed continuation send fails the run and acks', async () => {
    const env = { ...E, JOBS: fakeJobs({ failSend: true }).queue };
    const body = msgBody('cisa-kev');
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ more: true }) }),
    });
    expect(await runStep(body, 1, env, deps)).toEqual({ ack: true, status: 'failed' });
    expect(await getRun(body.runId)).toMatchObject({ status: 'failed', error: 'continuation not queued' });
    expect(await getCursor('cisa-kev')).toMatchObject({ value: 't1' });
  });

  it('writeRows throws: cursor unchanged, retry delay, error set, run stays running', async () => {
    const body = msgBody('cisa-kev');
    const deps = mkDeps({
      loadParser: async () => ({ parse: () => [kevRecord] }),
      link: async () => ({ rows: [{ table: 'vulns', op: 'upsert', row: {} }], docs: [], skipped: 0 }),
      writeRows: async () => {
        throw new Error('d1 busy');
      },
    });
    const out = await runStep(body, 2, E, deps);
    expect(out).toEqual({ ack: false, delaySeconds: 120, error: 'Error: d1 busy' });
    expect(await getCursor('cisa-kev')).toBeNull();
    expect(await getRun(body.runId)).toMatchObject({ status: 'running', error: 'Error: d1 busy' });
  });

  it('a deferred write is retryable', async () => {
    const deps = mkDeps({
      loadParser: async () => ({ parse: () => [kevRecord] }),
      link: async () => ({ rows: [{ table: 'vulns', op: 'upsert', row: {} }], docs: [], skipped: 0 }),
      writeRows: async () => ({ written: 0, statements: 0, deferred: true }),
    });
    const out = await runStep(msgBody('cisa-kev'), 1, E, deps);
    expect(out.ack).toBe(false);
  });

  it('the same message twice: no second continuation, counts unchanged', async () => {
    const jobs = fakeJobs();
    const env = { ...E, JOBS: jobs.queue };
    const body = msgBody('cisa-kev');
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ more: true }) }),
    });
    await runStep(body, 1, env, deps);
    const before = await getRun(body.runId);
    expect(await runStep(body, 2, env, deps)).toEqual({ ack: true, status: 'stale' });
    expect(jobs.sent).toHaveLength(1);
    expect(await getRun(body.runId)).toEqual(before);
  });

  it('a redelivery of a finished run is a duplicate', async () => {
    const body = msgBody('cve-list');
    const deps = mkDeps();
    await runStep(body, 1, E, deps);
    const before = await getRun(body.runId);
    expect(await runStep(body, 2, E, deps)).toEqual({ ack: true, status: 'duplicate' });
    expect(await getRun(body.runId)).toEqual(before);
  });

  it('cursor moved since planning: skipped, pattern not fetched', async () => {
    await seedCursor('cve-list', cursor('other'));
    let called = false;
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => {
          called = true;
          return 'changed';
        },
        fetch: async () => result(),
      }),
    });
    const body = msgBody('cve-list', { from: null });
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'stale' });
    expect(called).toBe(false);
    expect(await getRun(body.runId)).toMatchObject({
      status: 'skipped',
      error: 'cursor moved since planning',
    });
  });

  it('no parser: receipt only, found = items, nothing written, no cursor, `more` ignored', async () => {
    const jobs = fakeJobs();
    const body = msgBody('cve-list');
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ more: true }) }),
    });
    expect(await runStep(body, 1, { ...E, JOBS: jobs.queue }, deps)).toEqual({ ack: true, status: 'ok' });
    expect(await getRun(body.runId)).toMatchObject({ status: 'ok', found: 1, written: 0 });
    expect(await getCursor('cve-list')).toBeNull();
    expect(jobs.sent).toHaveLength(0);
    expect((await E.BUCKET.list()).objects).toHaveLength(1);
  });

  it('KV ingest off: the pattern is not called', async () => {
    await E.SETTINGS.put('source:cve-list', '{"ingest":false}');
    let called = false;
    const deps = mkDeps({
      patternFor: () => {
        called = true;
        throw new Error('no');
      },
    });
    const body = msgBody('cve-list');
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'skipped' });
    expect(called).toBe(false);
    expect((await getRun(body.runId))?.status).toBe('skipped');
  });

  describe('permanent failures', () => {
    it('NotImplementedError', async () => {
      const deps = mkDeps({
        patternFor: () => ({
          check: async () => 'changed',
          fetch: async () => {
            throw new NotImplementedError('x');
          },
        }),
      });
      const body = msgBody('cve-list');
      expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'failed' });
      expect(await getRun(body.runId)).toMatchObject({
        status: 'failed',
        error: 'NotImplementedError: not implemented: x',
      });
    });

    it('41 items', async () => {
      const items = Array.from({ length: 41 }, (_, i) => ({ id: String(i), body: i }));
      const deps = mkDeps({
        patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ items }) }),
      });
      const body = msgBody('cve-list');
      expect((await runStep(body, 1, E, deps)).ack).toBe(true);
      expect((await getRun(body.runId))?.status).toBe('failed');
      expect((await E.BUCKET.list()).objects).toHaveLength(0);
    });

    it('`more` without moving the cursor', async () => {
      const from = cursor('t1');
      await seedCursor('cve-list', from);
      const deps = mkDeps({
        patternFor: () => ({
          check: async () => 'changed',
          fetch: async () => result({ more: true, nextCursor: from }),
        }),
      });
      const body = msgBody('cve-list', { from });
      await runStep(body, 1, E, deps);
      expect((await getRun(body.runId))?.status).toBe('failed');
    });

    it('unknown parser', async () => {
      const deps = mkDeps({
        loadParser: async () => {
          throw new Error('unknown parser: kev');
        },
      });
      const body = msgBody('cisa-kev');
      expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'failed' });
      expect((await getRun(body.runId))?.error).toContain('unknown parser');
    });

    it('every item failing to parse; some failing is counted and kept', async () => {
      const bad = mkDeps({
        loadParser: async () => ({
          parse: () => {
            throw new Error('bad item');
          },
        }),
      });
      const b1 = msgBody('cisa-kev');
      await runStep(b1, 1, E, bad);
      expect(await getRun(b1.runId)).toMatchObject({ status: 'failed' });
      expect((await getRun(b1.runId))?.error).toContain('Error: bad item');

      let n = 0;
      const some = mkDeps({
        patternFor: () => ({
          check: async () => 'changed',
          fetch: async () =>
            result({
              items: [
                { id: 'a', body: 1 },
                { id: 'b', body: 2 },
              ],
            }),
        }),
        loadParser: async () => ({
          parse: () => {
            if (n++ === 0) throw new Error('bad item');
            return [kevRecord];
          },
        }),
      });
      const b2 = msgBody('cisa-kev');
      await runStep(b2, 1, E, some);
      expect(await getRun(b2.runId)).toMatchObject({
        status: 'ok',
        found: 1,
        error: 'parse failed for 1 of 2 items: Error: bad item',
      });
    });

    it('a link display-mode source with a parser', async () => {
      await E.SETTINGS.put('source:cisa-kev', '{"display":"link"}');
      const body = msgBody('cisa-kev');
      expect(await runStep(body, 1, E, mkDeps())).toEqual({ ack: true, status: 'failed' });
      expect((await getRun(body.runId))?.error).toContain('link-only');
    });

    it('unknown source id and an invalid body', async () => {
      const body = msgBody('no-such-source');
      expect(await runStep(body, 1, E, mkDeps())).toEqual({ ack: true, status: 'failed' });
      expect((await getRun(body.runId))?.status).toBe('failed');
      expect(await runStep({ sourceId: 'cve-list', runId: 'x', step: 0 }, 1, E, mkDeps())).toEqual({
        ack: true,
        status: 'invalid',
      });
    });
  });

  it('a link source receipt carries no bodies', async () => {
    const body = msgBody('zdi');
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () =>
          result({
            items: [{ id: 'z1', body: 'SECRET-BODY' }],
            receipt: {
              source: 'zdi',
              runId: 'r',
              fetchedAt: NOW.toISOString(),
              contentType: 'text/xml',
              body: 'SECRET-FEED',
            },
          }),
      }),
    });
    await runStep(body, 1, E, deps);
    const key = rawReceiptKey('zdi', body.runId, 0, new Date(decodeTime(body.runId)));
    const text = await gunzipText((await E.BUCKET.get(key)) as R2ObjectBody);
    expect(text).not.toContain('SECRET');
    expect(text).toContain('"id":"z1"');
    expect(text).toContain('"contentType":"text/xml"');
  });

  it('a binary receipt is base64', async () => {
    const body = msgBody('cve-list');
    const bytes = new Uint8Array([1, 2, 3, 255]);
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () =>
          result({
            items: [],
            receipt: {
              source: 'x',
              runId: 'r',
              fetchedAt: NOW.toISOString(),
              contentType: 'application/octet-stream',
              body: bytes.buffer,
            },
          }),
      }),
    });
    await runStep(body, 1, E, deps);
    const key = rawReceiptKey('cve-list', body.runId, 0, new Date(decodeTime(body.runId)));
    const line = JSON.parse(
      (await gunzipText((await E.BUCKET.get(key)) as R2ObjectBody)).split('\n')[0] as string,
    );
    expect(line).toMatchObject({ encoding: 'base64', body: btoa(String.fromCharCode(1, 2, 3, 255)) });
  });

  it('unknown fields land in KV, merged and capped', async () => {
    const deps = mkDeps({
      loadParser: async () => ({ parse: () => ({ records: [kevRecord], unknownFields: ['zeta', 'alpha'] }) }),
    });
    await runStep(msgBody('cisa-kev'), 1, E, deps);
    const first = JSON.parse((await E.SETTINGS.get('unknown-fields:cisa-kev')) as string);
    expect(first).toMatchObject({
      fields: ['zeta', 'alpha'],
      firstSeen: NOW.toISOString(),
      lastSeen: NOW.toISOString(),
    });

    await reset();
    await E.SETTINGS.put(
      'unknown-fields:cisa-kev',
      JSON.stringify({
        fields: ['old'],
        firstSeen: '2026-01-01T00:00:00.000Z',
        lastSeen: '2026-01-01T00:00:00.000Z',
      }),
    );
    const many = Array.from({ length: 80 }, (_, i) => `f${i}`.padEnd(150, 'x'));
    const deps2 = mkDeps({
      loadParser: async () => ({ parse: () => ({ records: [kevRecord], unknownFields: many }) }),
    });
    await runStep(msgBody('cisa-kev'), 1, E, deps2);
    const merged = JSON.parse((await E.SETTINGS.get('unknown-fields:cisa-kev')) as string);
    expect(merged.fields).toHaveLength(50);
    expect(merged.fields[0]).toBe('old');
    expect(merged.fields.every((f: string) => f.length <= 100)).toBe(true);
    expect(merged.firstSeen).toBe('2026-01-01T00:00:00.000Z');
    expect(merged.lastSeen).toBe(NOW.toISOString());
  });

  it('not-configured: skipped', async () => {
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () => {
          throw Object.assign(new Error('no urls'), { code: 'not-configured' });
        },
      }),
    });
    const body = msgBody('cve-list');
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'skipped' });
    expect((await getRun(body.runId))?.status).toBe('skipped');
  });

  it('not-configured from check() is skipped too', async () => {
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => {
          throw Object.assign(new Error('no urls'), { code: 'not-configured', retryable: false });
        },
        fetch: async () => result(),
      }),
    });
    const body = msgBody('cve-list');
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'skipped' });
    expect((await getRun(body.runId))?.status).toBe('skipped');
  });

  it('pattern errors follow `retryable`: cancelled retries, http is permanent', async () => {
    const failing = (code: string, retryable: boolean) =>
      mkDeps({
        patternFor: () => ({
          check: async () => 'changed',
          fetch: async () => {
            throw Object.assign(new Error('x'), { code, retryable });
          },
        }),
      });
    const b1 = msgBody('cve-list');
    expect(await runStep(b1, 1, E, failing('cancelled', true))).toMatchObject({ ack: false });
    expect((await getRun(b1.runId))?.status).toBe('running');
    const b2 = msgBody('cve-list');
    expect(await runStep(b2, 1, E, failing('http', false))).toEqual({ ack: true, status: 'failed' });
  });

  it('null nextCursor: no cursor is written, the run is recorded with its counts', async () => {
    const body = msgBody('cve-list');
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ nextCursor: null }) }),
      loadParser: async () => ({ parse: () => [] }),
    });
    expect(await runStep(body, 1, E, deps)).toMatchObject({ ack: true });
    expect(await getCursor('cve-list')).toBeNull();
    const run = await getRun(body.runId);
    expect(run?.found).toBe(1);
    expect(run?.finished_at).not.toBeNull();
  });

  it('null nextCursor keeps the stored cursor', async () => {
    const stored = cursor('t0');
    await seedCursor('cve-list', stored);
    const body = msgBody('cve-list', { from: stored });
    const deps = mkDeps({
      patternFor: () => ({ check: async () => 'changed', fetch: async () => result({ nextCursor: null }) }),
    });
    await runStep(body, 1, E, deps);
    expect(await getCursor('cve-list')).toMatchObject({ value: 't0' });
    expect((await getRun(body.runId))?.status).toBe('ok');
  });

  it('null nextCursor with `more` fails permanently', async () => {
    const body = msgBody('cve-list');
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () => result({ nextCursor: null, more: true }),
      }),
    });
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'failed' });
  });

  it('a first-run step (no stored cursor, from null) is not stale; a stored cursor with from null is', async () => {
    await seedCursor('cve-list', cursor('t0'));
    const body = msgBody('cve-list', { from: null });
    expect(await runStep(body, 1, E, mkDeps())).toEqual({ ack: true, status: 'stale' });
  });

  it('heavy with a null cursor sends no cursor field', async () => {
    const sent: Record<string, unknown>[] = [];
    const body = msgBody('cve-list');
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () =>
          result({
            nextCursor: null,
            heavy: { kind: 'big-file', sourceId: 'cve-list', reason: 'big', url: 'https://example.com/f' },
          }),
      }),
      startJob: async (req) => {
        sent.push(req as unknown as Record<string, unknown>);
        return {};
      },
    });
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'heavy' });
    expect(sent[0]).not.toHaveProperty('cursor');
  });

  it('the pattern context carries only the github and nvd credentials', async () => {
    let ctx: PatternContext | undefined;
    const env = { ...E, GITHUB_TOKEN: 'gh', NVD_API_KEY: 'nv', JOB_HMAC_SECRET: 'hmac', USER_AGENT: 'ua/1' };
    const deps = mkDeps({
      patternFor: () => ({
        check: async (c) => {
          ctx = c;
          return 'unchanged';
        },
        fetch: async () => result(),
      }),
    });
    await runStep(msgBody('cve-list'), 1, env, deps);
    expect(ctx?.credentials).toEqual({ github: 'gh', nvd: 'nv' });
    expect(ctx?.userAgent).toBe('ua/1');
    expect(ctx?.runId).toBeTruthy();
    expect(JSON.stringify(Object.keys(ctx as object).sort())).not.toContain('env');
    expect(JSON.stringify(ctx?.credentials)).not.toContain('hmac');
  });

  it('heavy: sends requestId and the pending cursor; the stored cursor stays', async () => {
    const stored = cursor('t0');
    await seedCursor('cve-list', stored);
    const sent: unknown[] = [];
    const next = cursor('t9');
    const body = msgBody('cve-list', { from: stored });
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () =>
          result({
            nextCursor: next,
            heavy: { kind: 'big-file', sourceId: 'cve-list', reason: 'big', url: 'https://example.com/f' },
          }),
      }),
      startJob: async (req) => {
        sent.push(req);
        return { jobId: 'j1' };
      },
    });
    expect(await runStep(body, 1, E, deps)).toEqual({ ack: true, status: 'heavy' });
    expect(sent).toEqual([
      {
        kind: 'big-file',
        sourceId: 'cve-list',
        reason: 'big',
        url: 'https://example.com/f',
        requestId: `${body.runId}-0`,
        cursor: next,
      },
    ]);
    expect(await getCursor('cve-list')).toMatchObject({ value: 't0' });
    expect((await getRun(body.runId))?.status).toBe('heavy');
  });

  it('errors are stored without URL query strings, capped at 500 characters', async () => {
    const deps = mkDeps({
      patternFor: () => ({
        check: async () => 'changed',
        fetch: async () => {
          throw new Error(`GET https://example.com/a?apiKey=SECRET failed ${'x'.repeat(900)}`);
        },
      }),
    });
    const body = msgBody('cve-list');
    const out = await runStep(body, 1, E, deps);
    expect(out.ack).toBe(false);
    const run = await getRun(body.runId);
    expect(run?.error).not.toContain('SECRET');
    expect((run?.error ?? '').length).toBeLessThanOrEqual(500);
    expect(deps.logs.join('\n')).not.toContain('SECRET');
  });

  it('a stale running run that is not its own keeps its status (seeded row)', async () => {
    const id = newRunId();
    await seedRun(id, 'cve-list', NOW, 'failed');
    expect(await runStep(msgBody('cve-list', { runId: id }), 1, E, mkDeps())).toEqual({
      ack: true,
      status: 'duplicate',
    });
  });
});
