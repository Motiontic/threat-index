import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { JobDeps } from '../types.ts';

/** A scratch directory named from the job id, removed afterwards. */
export async function withScratch<T>(jobId: string, fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), `job-${jobId.replace(/[^A-Za-z0-9-]/g, '')}-`));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export const lakeDeps = (
  jobId: string,
  deps: JobDeps,
  log: (m: string, x?: Record<string, unknown>) => void,
) => ({
  jobId,
  ...(deps.execFile ? { execFile: deps.execFile } : {}),
  ...(deps.duckdb ? { duckdb: deps.duckdb } : {}),
  log,
});

export const YMD = /^\d{4}-\d{2}-\d{2}$/;

/** UTC midnight of `YYYY-MM-DD`, in ms. Throws on a date that does not exist. */
export function dayStartMs(day: string): number {
  const ms = Date.parse(`${day}T00:00:00Z`);
  if (!YMD.test(day) || Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== day)
    throw new Error('not a YYYY-MM-DD day');
  return ms;
}
export const dayString = (ms: number): string => new Date(ms).toISOString().slice(0, 10);
