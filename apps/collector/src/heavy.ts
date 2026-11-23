import type { JobRequest } from '@ti/core/control';
import { SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';
import type { Env } from './env';
import { PermanentError } from './errors';

const JOBS_PATH = '/internal/jobs';

/** Asks ti-api (over the service binding) to start an E2B job. Signed with JOB_HMAC_SECRET. */
export async function startHeavyJob(
  env: Pick<Env, 'API' | 'JOB_HMAC_SECRET'>,
  req: JobRequest,
  now: Date,
): Promise<{ jobId?: string }> {
  if (!env.API) throw new PermanentError('API binding is not configured');
  if (!env.JOB_HMAC_SECRET) throw new PermanentError('JOB_HMAC_SECRET is not set');

  const body = JSON.stringify(req);
  const timestamp = Math.floor(now.getTime() / 1000);
  const signature = await signRequest(env.JOB_HMAC_SECRET, 'POST', JOBS_PATH, timestamp, body);
  const res = await env.API.fetch(`https://ti-api.internal${JOBS_PATH}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [TIMESTAMP_HEADER]: String(timestamp),
      [SIGNATURE_HEADER]: signature,
    },
    body,
  });

  if (res.status >= 200 && res.status < 300) {
    const json = (await res.json().catch(() => null)) as { jobId?: unknown } | null;
    return typeof json?.jobId === 'string' ? { jobId: json.jobId } : {};
  }
  // 501 (job_kind_not_ready) and every other 4xx are permanent; 429 and the other 5xx can pass.
  if (res.status !== 501 && (res.status === 429 || res.status >= 500)) {
    throw new Error(`ti-api returned ${res.status}`);
  }
  throw new PermanentError(`ti-api returned ${res.status} ${await errorCode(res)}`.trim());
}

/** The `error` code from a JSON error body, never the rest of it. */
async function errorCode(res: Response): Promise<string> {
  const json = (await res.json().catch(() => null)) as { error?: unknown } | null;
  const code = json?.error;
  return typeof code === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(code) ? code : '';
}
