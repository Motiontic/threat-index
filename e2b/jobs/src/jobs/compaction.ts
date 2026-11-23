import { NotImplementedError } from '@ti/core/errors';
import type { Job, JobContext } from '../types.ts';

export async function run(_job: Job, _ctx: JobContext): Promise<void> {
  throw new NotImplementedError('job compaction');
}
