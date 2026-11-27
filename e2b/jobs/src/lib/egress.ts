import type { JobDeps } from '../types.ts';

const EGRESS_PROBE = 'https://1.1.1.1/';
const EGRESS_TIMEOUT_MS = 5000;

/**
 * Fetches `https://1.1.1.1/`. An answer of any kind means the sandbox is not restricted to the API, and the job
 * stops with `<job>: egress not restricted`.
 */
export async function checkEgress(job: string, jobDeps: JobDeps): Promise<void> {
  const doFetch = jobDeps.fetch ?? fetch;
  let reached = false;
  try {
    await doFetch(EGRESS_PROBE, { signal: AbortSignal.timeout(EGRESS_TIMEOUT_MS) });
    reached = true;
  } catch {
    /* blocked, as it should be */
  }
  if (reached) throw new Error(`${job}: egress not restricted`);
}
