import { env } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import worker from '../src/index';
import { dueSources } from '../src/planner';

it('scheduled() on the 3-hourly cron sends one job per due source to the queue', async () => {
  const sent: { body: { sourceId: string; step: number } }[] = [];
  const realJobs = env.JOBS;
  const jobs = {
    sendBatch: (msgs: typeof sent) => {
      sent.push(...msgs);
      return realJobs.sendBatch(msgs as never);
    },
  };
  const due = dueSources('0 */3 * * *');
  expect(due.length).toBeGreaterThan(0);

  await worker.scheduled(
    { cron: '0 */3 * * *', scheduledTime: Date.now() } as ScheduledController,
    {
      ...env,
      JOBS: jobs,
    } as never,
  );

  expect(sent.map((m) => m.body.sourceId).sort()).toEqual(due.map((s) => s.id).sort());
  expect(sent.every((m) => m.body.step === 0)).toBe(true);
  // `wait` sources never run.
  expect(sent.map((m) => m.body.sourceId)).not.toContain('hhs-ocr-wait');
});
