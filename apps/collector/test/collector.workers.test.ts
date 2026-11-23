import { env } from 'cloudflare:workers';
import { SOURCE_BY_ID } from '@ti/sources/registry';
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
  // `wait` sources never run. Statuses come from the real registry, not made-up ids.
  const ids = sent.map((m) => m.body.sourceId);
  const waiting = [...SOURCE_BY_ID.values()].filter((s) => s.licence === 'wait' && s.cadence === '3h');
  expect(waiting.map((s) => s.id)).toContain('ransomware-live'); // guards against a vacuous check
  for (const id of ids) expect(SOURCE_BY_ID.get(id)?.licence).not.toBe('wait');
  for (const s of waiting) expect(ids).not.toContain(s.id);
});
