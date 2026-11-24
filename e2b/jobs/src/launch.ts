/**
 * Launcher for the job process: `node /app/launch.mjs` (started by ti-api through the E2B SDK, which does not
 * pass the image's ENV, so the heap limit is set here, on the job process itself).
 * It runs `run.mjs` as a child with `--max-old-space-size`. The job reports its own success and its caught
 * errors. If the child dies without that (out of memory, an uncaught error, a signal), this process reports
 * `complete({ ok: false })`, so the job row ends `failed` instead of staying `running`. The API treats a repeated
 * complete on a finished job as a no-op, so reporting twice is harmless.
 * The job key lives only in this process and the `run.mjs` child (which removes it from its own environment
 * before it starts anything); no further process ever receives `JOB_JSON`.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createJobApi, type JobApi } from './client.ts';
import { parseJob } from './parse-job.ts';
import type { Job } from './types.ts';

/** Below the template's 4096 MB (e2b/build-template.mjs): room for the OS, DuckDB and buffers outside the heap. */
export const JOB_HEAP_MB = 3072;
const STDERR_TAIL_BYTES = 4096;

export interface SuperviseOpts {
  api: JobApi;
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv; // the child's environment, `JOB_JSON` included
  log?: (line: string) => void;
}

/** A short, key-free reason for the job row. */
export function describeExit(code: number | null, signal: NodeJS.Signals | null, stderrTail: string): string {
  const oom = /heap out of memory|allocation failed/i.test(stderrTail);
  const how = signal ? `killed by ${signal}` : `exited with code ${code}`;
  return `job process ${how}${oom ? ' (out of memory)' : ''}`;
}

/** Runs the child, passes its output through, and reports a failure if it left without reporting. Returns the exit code. */
export async function supervise(job: Job, opts: SuperviseOpts): Promise<number> {
  const out = opts.log ?? ((line: string) => console.log(line));
  const child = spawn(opts.command, opts.args, { env: opts.env, stdio: ['ignore', 'inherit', 'pipe'] });
  let tail = '';
  child.stderr.on('data', (chunk: Buffer) => {
    process.stderr.write(chunk);
    tail = (tail + chunk.toString('utf8')).slice(-STDERR_TAIL_BYTES);
  });
  const { code, signal } = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve) => {
      child.once('error', (err) => {
        tail += String(err);
        resolve({ code: 127, signal: null });
      });
      child.once('close', (c, s) => resolve({ code: c, signal: s }));
    },
  );
  if (code === 0) return 0;
  const error = describeExit(code, signal, tail);
  out(JSON.stringify({ level: 'error', msg: error, id: job.id }));
  try {
    await opts.api.complete({ ok: false, error });
  } catch {
    out(JSON.stringify({ level: 'error', msg: 'could not report failure', id: job.id }));
  }
  return code ?? 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let job: Job;
  const jobJson = process.env.JOB_JSON;
  try {
    job = parseJob(process.argv[2] ?? jobJson);
  } catch (err) {
    console.error(JSON.stringify({ level: 'error', msg: err instanceof Error ? err.message : String(err) }));
    process.exit(1);
  }
  const run = fileURLToPath(new URL('./run.mjs', import.meta.url));
  const env = { ...process.env, JOB_JSON: JSON.stringify(job) };
  delete process.env.JOB_JSON;
  process.exit(
    await supervise(job, {
      api: createJobApi(job),
      command: process.execPath,
      args: [`--max-old-space-size=${JOB_HEAP_MB}`, run],
      env,
    }),
  );
}
