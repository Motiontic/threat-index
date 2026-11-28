/**
 * Starts any job on a deployed ti-api and polls it.
 *   JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs start-job -- --api <origin> --kind <kind>
 *     (kind: first-load, epss-diff, big-file, nightly-fold, search-index, affected-backfill, echo)
 *     [--source <id>] [--url <https>] [--day YYYY-MM-DD] [--no-wait]
 * Prints the job id and status only. Exit 0 only when the job ends `complete` (with --no-wait: when it started).
 */
import { pathToFileURL } from 'node:url';
import { type OpsDeps, pollJob, signedSender } from './lib/ops.ts';
import { newUlid } from './lib/ulid.ts';

export interface StartArgs {
  api: string;
  kind: string;
  source?: string;
  url?: string;
  day?: string;
  wait: boolean;
}

export const KINDS = [
  'first-load',
  'epss-diff',
  'big-file',
  'nightly-fold',
  'search-index',
  'affected-backfill',
  'echo',
];

export function parseArgs(argv: string[]): StartArgs | string {
  const out: Partial<StartArgs> = { wait: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') continue;
    if (a === '--no-wait') out.wait = false;
    else if (a === '--api' || a === '--kind' || a === '--source' || a === '--url' || a === '--day') {
      const v = argv[++i];
      if (!v || v.startsWith('--')) return `${a} needs a value`;
      out[a.slice(2) as 'api' | 'kind' | 'source' | 'url' | 'day'] = v;
    } else return `unknown argument: ${a}`;
  }
  if (!out.api) return '--api is required';
  if (!out.kind || !KINDS.includes(out.kind)) return `--kind must be one of ${KINDS.join(', ')}`;
  return out as StartArgs;
}

export async function startJob(args: StartArgs, secret: string, deps: OpsDeps = {}): Promise<number> {
  const print = deps.print ?? ((l: string) => console.log(l));
  const send = signedSender(args.api.replace(/\/$/, ''), secret, deps);
  const body = {
    kind: args.kind,
    reason: 'started with start-job',
    requestId: deps.now ? newUlid(deps.now()) : newUlid(),
    ...(args.source ? { sourceId: args.source } : {}),
    ...(args.url ? { url: args.url } : {}),
    ...(args.day ? { day: args.day } : {}),
  };
  const start = await send('POST', '/internal/jobs', JSON.stringify(body));
  if (start.status !== 200 && start.status !== 201) {
    print(`start failed: status ${start.status}`);
    return 1;
  }
  const { jobId, status: first } = (await start.json()) as { jobId: string; status: string };
  if (!args.wait) {
    print(`job ${jobId} ${first}`);
    return 0;
  }
  const status = await pollJob(send, jobId, deps);
  print(`job ${jobId} ${status}`);
  return status === 'complete' ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = parseArgs(process.argv.slice(2));
  const secret = process.env.JOB_HMAC_SECRET;
  if (typeof args === 'string' || !secret) {
    console.error(
      `${typeof args === 'string' ? `${args}\n` : ''}usage: JOB_HMAC_SECRET=… start-job --api <origin> --kind <${KINDS.join('|')}> [--source <id>] [--url <https>] [--day YYYY-MM-DD] [--no-wait]`,
    );
    process.exit(2);
  }
  process.exit(await startJob(args, secret));
}
