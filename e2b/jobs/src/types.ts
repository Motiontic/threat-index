export const JOB_KINDS = [
  'first-load',
  'epss-diff',
  'big-file',
  'nightly-fold',
  'search-index',
  'compaction',
  'deep-query',
] as const;
export type JobKind = (typeof JOB_KINDS)[number];

export interface Job {
  id: string;
  kind: JobKind;
  sourceId?: string;
  apiBase: string; // ti-api, for upload-urls and complete callbacks (HMAC-signed)
  hmac: string; // per-job signature issued by the API; not a long-lived secret
}

export interface JobContext {
  log(msg: string, extra?: Record<string, unknown>): void;
}

/** What every `jobs/<kind>.ts` exports. */
export type RunJob = (job: Job, ctx: JobContext) => Promise<void>;
