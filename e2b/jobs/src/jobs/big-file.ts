import type { Job, JobContext, JobDeps } from '../types.ts';
import { runLoad } from './first-load.ts';

/** A large update: the same load as `first-load`, with update semantics (the change window starts at `from`). */
export async function run(job: Job, ctx: JobContext, deps: JobDeps = {}): Promise<void> {
  await runLoad(job, ctx, deps, 'update');
}
