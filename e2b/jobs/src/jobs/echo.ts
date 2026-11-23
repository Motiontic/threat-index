import { inboxManifestKey } from '@ti/core/inbox';
import { jobPrefix } from '@ti/core/r2-keys';
import type { Job, JobContext } from '../types.ts';

/** A dummy job: proves a sandbox can start, upload through presigned URLs and complete. */
export async function run(job: Job, ctx: JobContext): Promise<void> {
  const at = new Date().toISOString();
  await ctx.api.upload([
    {
      key: `${jobPrefix(job.id)}echo.json`,
      body: JSON.stringify({ id: job.id, kind: job.kind, at, node: process.version }),
      contentType: 'application/json',
    },
    {
      key: inboxManifestKey(job.id),
      body: JSON.stringify({ jobId: job.id, createdAt: at, chunks: [] }),
      contentType: 'application/json',
    },
  ]);
  ctx.log('echo uploaded');
}
