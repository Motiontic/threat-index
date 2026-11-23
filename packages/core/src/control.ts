import type { Cursor } from './types';

export const RUN_STATUSES = ['running', 'unchanged', 'ok', 'heavy', 'skipped', 'failed'] as const;
export type RunStatus = (typeof RUN_STATUSES)[number];

export const JOB_STATUSES = ['queued', 'starting', 'running', 'complete', 'failed', 'timed_out'] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

/**
 * What the collector sends to ti-api to start an E2B job.
 *
 * `POST /internal/jobs` answers `201 { jobId, status }` for a new job and
 * `200 { jobId, status, existing: true }` when the request's job, or an active job of the same kind and
 * source, already exists. Callers treat `429`, `502` and `503` as retryable, and every other `4xx` and
 * `501` as permanent.
 */
export interface JobRequest {
  /**
   * Deterministic for the step that asked (`<runId>-<step>`). ti-api uses it as the job id, so a
   * redelivered request finds the existing job instead of starting a second sandbox.
   */
  requestId: string;
  kind: 'first-load' | 'epss-diff' | 'big-file';
  sourceId: string;
  reason: string;
  url?: string;
  /**
   * The cursor the source moves to once this job has done its work. ti-api keeps it with the job
   * (under jobs/<id>/) and writes it to ti_control.cursors only when the job completes successfully.
   */
  cursor?: Cursor;
}
