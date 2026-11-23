/** Shared by the ops scripts (`round-trip`, `start-job`): ops-key signed calls and job polling. */
import { SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';

export interface OpsDeps {
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  print?: (line: string) => void;
  pollMs?: number;
  maxMs?: number;
}

/** A call signed with the ops key. The signed path is `path` as given (no query is used on these routes). */
export function signedSender(api: string, secret: string, deps: OpsDeps = {}) {
  const doFetch = deps.fetch ?? fetch;
  const now = deps.now ?? Date.now;
  return async (method: 'GET' | 'POST', path: string, body: string): Promise<Response> => {
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
}
export type SignedSend = ReturnType<typeof signedSender>;

export const FINAL_STATUSES = ['complete', 'failed', 'timed_out'];

/** Polls `GET /internal/jobs/:id` until the job ends or `maxMs` passes. Returns the last status seen. */
export async function pollJob(send: SignedSend, jobId: string, deps: OpsDeps = {}): Promise<string> {
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deadline = now() + (deps.maxMs ?? 10 * 60 * 1000);
  let status = 'unknown';
  while (now() < deadline) {
    const res = await send('GET', `/internal/jobs/${jobId}`, '');
    if (res.ok) {
      status = ((await res.json()) as { status: string }).status;
      if (FINAL_STATUSES.includes(status)) break;
    } else status = `http ${res.status}`;
    await sleep(deps.pollMs ?? 5000);
  }
  return status;
}
