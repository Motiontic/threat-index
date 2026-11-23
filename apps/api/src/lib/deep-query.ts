import type { Credit } from '@ti/core/api';
import { hmacHex } from './auth';
import type { DeepTemplate } from './deep-templates';

export const DEEP_RATE_PER_HOUR = 10;
/** Deep queries active across all users, so heavy jobs keep two of the MAX_ACTIVE_JOBS slots. */
export const MAX_ACTIVE_DEEP = 3;
export const DEEP_QUERY_TIMEOUT_MS = 5 * 60 * 1000; // the sandbox's own timeout
export const DEEP_QUERY_STALE_MS = 6 * 60 * 1000; // active rows older than this become timed_out
export const MAX_DEEP_BODY_BYTES = 2 * 1024;
export const MAX_RESULT_BYTES = 5 * 1024 * 1024;
export const HOUR_MS = 60 * 60 * 1000;

export const DEEP_ERRORS = [
  'invalid_params',
  'scan_too_large',
  'query_failed',
  'timed_out',
  'result_missing',
] as const;
export type DeepError = (typeof DEEP_ERRORS)[number];

export interface DeepQueryResult {
  template: DeepTemplate;
  rows: Record<string, unknown>[];
  rowCount: number;
  truncated: boolean;
  sources: string[];
  scanned: { objects: number; bytes: number };
  tookMs: number;
}

export interface DeepQueryStatus {
  id: string;
  template: DeepTemplate;
  params: Record<string, string>;
  status: 'running' | 'complete' | 'failed';
  createdAt: string;
  finishedAt: string | null;
  error?: DeepError;
  result?: DeepQueryResult;
  credits?: Credit[];
}

/** The owner tag stored in `jobs.source_id`: a keyed hash, so no Clerk id reaches D1 or R2. */
export async function deepOwner(secret: string, userId: string): Promise<string> {
  return `dq:${(await hmacHex(secret, `deep-query-owner:${userId}`)).slice(0, 32)}`;
}

/** `jobs.error` → the public code. Only `deep-query: <listed code>` passes through. */
export function publicError(raw: string | null): DeepError {
  const m = /^deep-query: ([a-z_]+)$/.exec(raw ?? '');
  const code = m?.[1];
  if (
    code &&
    (DEEP_ERRORS as readonly string[]).includes(code) &&
    code !== 'timed_out' &&
    code !== 'result_missing'
  )
    return code as DeepError;
  return 'query_failed';
}
