/**
 * E2B job runner. See docs/IMPLEMENTATION_PLAN.md §6.
 * Usage (in a sandbox or locally): node run.mjs '<job-json>'  (or JOB_JSON in the environment)
 * Each job kind lives in jobs/<kind>.ts and exports run(job, ctx). This file only dispatches, then tells
 * ti-api how it went: `complete({ ok: true })`, or `complete({ ok: false, error })` and exit 1.
 */
import { pathToFileURL } from 'node:url';
import { type ClientDeps, createJobApi, type JobApi } from './client.ts';
import { parseJob } from './parse-job.ts';
import type { Job, JobContext, JobKind, RunJob } from './types.ts';

export { parseJob };

// A map, not a computed import, so the bundler sees every job.
const JOBS: Record<JobKind, () => Promise<{ run: RunJob }>> = {
  'first-load': () => import('./jobs/first-load.ts'),
  'epss-diff': () => import('./jobs/epss-diff.ts'),
  'big-file': () => import('./jobs/big-file.ts'),
  'nightly-fold': () => import('./jobs/nightly-fold.ts'),
  'search-index': () => import('./jobs/search-index.ts'),
  'affected-backfill': () => import('./jobs/affected-backfill.ts'),
  compaction: () => import('./jobs/compaction.ts'),
  'deep-query': () => import('./jobs/deep-query.ts'),
  echo: () => import('./jobs/echo.ts'),
};

export interface MainDeps {
  api?: JobApi;
  client?: ClientDeps;
  log?: (line: string) => void;
}

/** Runs one job and reports to the API. Returns the process exit code. */
export async function main(job: Job, deps: MainDeps = {}): Promise<number> {
  const out = deps.log ?? ((line: string) => console.log(line));
  const api = deps.api ?? createJobApi(job, deps.client);
  const ctx: JobContext = {
    api,
    log: (msg, extra) => out(JSON.stringify({ level: 'info', msg, id: job.id, ...extra })),
  };
  try {
    ctx.log('job start', { kind: job.kind });
    const { run } = await JOBS[job.kind]();
    await run(job, ctx);
    await api.complete({ ok: true });
    ctx.log('job done');
    return 0;
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    out(JSON.stringify({ level: 'error', msg: error, id: job.id }));
    try {
      await api.complete({ ok: false, error });
    } catch {
      out(JSON.stringify({ level: 'error', msg: 'could not report failure', id: job.id }));
    }
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let job: Job;
  try {
    job = parseJob(process.argv[2] ?? process.env.JOB_JSON);
  } catch (err) {
    console.error(JSON.stringify({ level: 'error', msg: err instanceof Error ? err.message : String(err) }));
    process.exit(1);
  }
  // Child processes (DuckDB, shells) must not inherit the job key.
  delete process.env.JOB_JSON;
  process.exit(await main(job));
}
