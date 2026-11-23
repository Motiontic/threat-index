import type { JobApi } from './client.ts';

export const JOB_KINDS = [
  'first-load',
  'epss-diff',
  'big-file',
  'nightly-fold',
  'search-index',
  'compaction',
  'deep-query',
  'echo', // a dummy job that proves the bridge: uploads one object and an empty manifest
] as const;
export type JobKind = (typeof JOB_KINDS)[number];

export interface Job {
  id: string;
  kind: JobKind;
  sourceId?: string;
  url?: string;
  apiBase: string; // ti-api, for upload-urls and complete callbacks (HMAC-signed)
  hmac: string; // per-job signature issued by the API; not a long-lived secret
}

export interface JobContext {
  log(msg: string, extra?: Record<string, unknown>): void;
  api: JobApi;
}

/** What every `jobs/<kind>.ts` exports. */
export type RunJob = (job: Job, ctx: JobContext) => Promise<void>;
