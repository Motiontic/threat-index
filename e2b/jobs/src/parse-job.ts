import { JOB_KINDS, type Job, type JobKind } from './types.ts';

/** Parses the job description. Throws a clear error for anything unusable. */
export function parseJob(text: string | undefined): Job {
  if (!text) throw new Error('no job description: pass JSON as argv[2] or JOB_JSON');
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('job description is not valid JSON');
  }
  const j = data as Partial<Job> | null;
  if (!j || typeof j !== 'object') throw new Error('job description is not an object');
  if (typeof j.id !== 'string' || !j.id) throw new Error('job description has no id');
  if (typeof j.kind !== 'string' || !JOB_KINDS.includes(j.kind as JobKind))
    throw new Error(`unknown job kind: ${String(j.kind)}`);
  if (typeof j.apiBase !== 'string' || !j.apiBase) throw new Error('job description has no apiBase');
  if (typeof j.hmac !== 'string' || !j.hmac) throw new Error('job description has no hmac');
  return j as Job;
}
