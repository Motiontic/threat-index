/**
 * Staging check: start an echo job, poll until it ends.
 *   JOB_HMAC_SECRET=… pnpm --filter @ti/e2b-jobs round-trip -- --api <origin>
 * Prints the job id and status only. Exit 0 only when the job ends `complete`.
 */
import { pathToFileURL } from 'node:url';
import { SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';

export interface RoundTripDeps {
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  print?: (line: string) => void;
  pollMs?: number;
  maxMs?: number;
}

export async function roundTrip(api: string, secret: string, deps: RoundTripDeps = {}): Promise<number> {
  const doFetch = deps.fetch ?? fetch;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const print = deps.print ?? ((l: string) => console.log(l));
  const pollMs = deps.pollMs ?? 5000;
  const maxMs = deps.maxMs ?? 10 * 60 * 1000;

  const send = async (method: 'GET' | 'POST', path: string, body: string) => {
    const ts = Math.floor(now() / 1000);
    return doFetch(`${api}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        [TIMESTAMP_HEADER]: String(ts),
        [SIGNATURE_HEADER]: await signRequest(secret, method, path, ts, body),
      },
      ...(method === 'POST' ? { body } : {}),
    });
  };

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
  const deadline = now() + maxMs;
  let status = 'unknown';
  while (now() < deadline) {
    const res = await send('GET', `/internal/jobs/${jobId}`, '');
    if (res.ok) {
      status = ((await res.json()) as { status: string }).status;
      if (status === 'complete' || status === 'failed' || status === 'timed_out') break;
    } else status = `http ${res.status}`;
    await sleep(pollMs);
  }
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
