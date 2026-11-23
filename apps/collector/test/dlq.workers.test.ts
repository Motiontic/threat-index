import { createExecutionContext, createMessageBatch, getQueueResult } from 'cloudflare:test';
import { beforeEach, expect, it } from 'vitest';
import worker from '../src/index';
import { E, getRun, msgBody, NOW, newRunId, reset, seedRun } from './helpers';

beforeEach(reset);

async function deliver(queue: string, bodies: unknown[]) {
  const batch = createMessageBatch(
    queue,
    bodies.map((body, i) => ({ id: `m${i}`, timestamp: NOW, attempts: 1, body })),
  );
  const ctx = createExecutionContext();
  await worker.queue(batch, E);
  return getQueueResult(batch, ctx);
}

it('a running run becomes failed with the previous error; a finished one is left alone', async () => {
  const running = msgBody('osv');
  const done = msgBody('nvd');
  await seedRun(running.runId, 'osv', NOW, 'running', { error: 'Error: d1 busy' });
  await seedRun(done.runId, 'nvd', NOW, 'ok');
  const out = await deliver('ti-jobs-dlq', [running, done]);
  expect(out.explicitAcks.sort()).toEqual(['m0', 'm1']);
  expect(await getRun(running.runId)).toMatchObject({
    status: 'failed',
    error: 'dead-lettered after 6 attempts: Error: d1 busy',
  });
  expect((await getRun(running.runId))?.finished_at).not.toBeNull();
  expect(await getRun(done.runId)).toMatchObject({ status: 'ok', error: null });
});

it('no row: inserts a failed one (staging queue name too)', async () => {
  const body = msgBody('osv');
  const out = await deliver('ti-jobs-dlq-staging', [body]);
  expect(out.explicitAcks).toEqual(['m0']);
  expect(await getRun(body.runId)).toMatchObject({
    source_id: 'osv',
    status: 'failed',
    error: 'dead-lettered after 6 attempts: none',
  });
});

it('invalid bodies are acked and write nothing', async () => {
  const out = await deliver('ti-jobs-dlq', [{ nope: 1 }, { sourceId: 'osv', runId: newRunId(), step: 0 }]);
  expect(out.explicitAcks.sort()).toEqual(['m0', 'm1']);
  expect((await E.DB_CONTROL.prepare('SELECT COUNT(*) AS n FROM runs').first<{ n: number }>())?.n).toBe(0);
});

it('a D1 error retries the message', async () => {
  const batch = createMessageBatch('ti-jobs-dlq', [
    { id: 'm0', timestamp: NOW, attempts: 1, body: msgBody('osv') },
  ]);
  const ctx = createExecutionContext();
  const broken = {
    ...E,
    DB_CONTROL: {
      prepare: () => {
        throw new Error('d1 down');
      },
    },
  } as never;
  await worker.queue(batch, broken);
  const out = await getQueueResult(batch, ctx);
  expect(out.explicitAcks).toEqual([]);
  expect(out.retryMessages.map((m) => m.msgId)).toEqual(['m0']);
});

it('a ti-jobs batch is not routed to the DLQ recorder (invalid bodies are acked as steps)', async () => {
  const out = await deliver('ti-jobs-staging', [{ nope: 1 }]);
  expect(out.explicitAcks).toEqual(['m0']);
});
