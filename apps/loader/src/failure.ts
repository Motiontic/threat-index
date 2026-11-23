import { reserveWrites } from '@ti/core/budget';

const MAX_REASON = 500;

/**
 * Marks the job failed and keeps the first reason. `reason` is "<chunkKey>: <what went wrong>". Counted as
 * one steady write. With no job row, nothing changes and the log line is the only record.
 * Returns whether a job row was updated.
 */
export async function recordLoadFailure(
  db: D1Database,
  jobId: string,
  reason: string,
  now: Date,
): Promise<boolean> {
  const res = await db
    .prepare(
      "UPDATE jobs SET status = 'failed', error = COALESCE(error, ?1), finished_at = COALESCE(finished_at, ?2) WHERE id = ?3",
    )
    .bind(reason.slice(0, MAX_REASON), now.toISOString(), jobId)
    .run();
  const changed = (res.meta.changes ?? 0) > 0;
  if (changed) await reserveWrites(db, 1, 'steady', now);
  return changed;
}
