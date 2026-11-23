/**
 * Staging check: start an echo job, poll until it ends.
 *   JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs round-trip -- --api <origin>
 * Prints the job id and status only. Exit 0 only when the job ends `complete`.
 */
import { pathToFileURL } from 'node:url';
import { type OpsDeps, pollJob, signedSender } from './lib/ops.ts';

export type RoundTripDeps = OpsDeps;

export async function roundTrip(api: string, secret: string, deps: RoundTripDeps = {}): Promise<number> {
  const print = deps.print ?? ((l: string) => console.log(l));
  const send = signedSender(api, secret, deps);
  const start = await send(
    'POST',
    '/internal/jobs',
    JSON.stringify({ kind: 'echo', reason: 'round-trip check' }),
  );
  if (start.status !== 200 && start.status !== 201) {
    print(`start failed: status ${start.status}`);
    return 1;
  }
  const { jobId } = (await start.json()) as { jobId: string };
  const status = await pollJob(send, jobId, deps);
  print(`job ${jobId} ${status}`);
  return status === 'complete' ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const i = process.argv.indexOf('--api');
  const api = i >= 0 ? process.argv[i + 1] : undefined;
  const secret = process.env.JOB_HMAC_SECRET;
  if (!api || !secret) {
    console.error('usage: JOB_HMAC_SECRET=… round-trip --api <origin>');
    process.exit(2);
  }
  process.exit(await roundTrip(api.replace(/\/$/, ''), secret));
}
