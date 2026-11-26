import type { JobApi } from './client.ts';
import type { LakeDeps } from './lib/lake.ts';

export const JOB_KINDS = [
  'first-load',
  'epss-diff',
  'big-file',
  'nightly-fold',
  'search-index',
  'affected-backfill',
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
  day?: string; // YYYY-MM-DD (UTC), for the global jobs
  apiBase: string; // ti-api, for upload-urls and complete routes (HMAC-signed)
  hmac: string; // per-job signature issued by the API; not a long-lived secret
}

export interface JobContext {
  log(msg: string, extra?: Record<string, unknown>): void;
  api: JobApi;
}

/** What every `jobs/<kind>.ts` exports. */
export type RunJob = (job: Job, ctx: JobContext, deps?: JobDeps) => Promise<void>;

/** What tests replace: the network, the clock, DuckDB. Jobs take it as an optional third argument. */
export interface JobDeps {
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  duckdb?: LakeDeps['duckdb'];
  execFile?: LakeDeps['execFile'];
}
