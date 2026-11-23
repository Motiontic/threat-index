/**
 * E2B job runner. See docs/IMPLEMENTATION_PLAN.md §6.
 * Usage (in a sandbox or locally): node run.ts '<job-json>'
 * Each job kind lives in jobs/<kind>.ts and exports run(job, ctx). This file only dispatches.
 */
import { JOB_KINDS, type Job, type JobContext, type JobKind } from './types.ts';

const job = JSON.parse(process.argv[2] ?? process.env.JOB_JSON ?? '{}') as Job;

const ctx: JobContext = {
  log: (msg, extra) => console.log(JSON.stringify({ level: 'info', msg, id: job.id, ...extra })),
};

async function main(): Promise<void> {
  if (!job.id || !job.kind) throw new Error('missing job description');
  if (!JOB_KINDS.includes(job.kind as JobKind)) throw new Error(`unknown job kind: ${job.kind}`);
  ctx.log('job start', { kind: job.kind });
  const { run } = (await import(`./jobs/${job.kind}.ts`)) as {
    run: (j: Job, c: JobContext) => Promise<void>;
  };
  await run(job, ctx);
  ctx.log('job done');
}

main().catch((err) => {
  console.error(JSON.stringify({ level: 'error', msg: String(err), id: job.id }));
  process.exit(1);
});
