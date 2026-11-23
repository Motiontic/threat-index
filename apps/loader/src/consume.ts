import { reserveWrites, secondsUntilUtcMidnight } from '@ti/core/budget';

/** ti-loader. See docs/IMPLEMENTATION_PLAN.md §7. One message = one inbox chunk (≤ 500 rows). */
export interface Env {
  DB_CONTROL: D1Database;
  BUCKET: R2Bucket;
}

export interface LoadMessage {
  jobId: string;
  chunkKey: string; // inbox/<job>/<n>.ndjson.gz
  rows: number;
  priority: 'steady' | 'first-load';
}

const MAX_QUEUE_DELAY_SECONDS = 12 * 60 * 60; // verify current Queues limit

export async function consume(batch: MessageBatch<LoadMessage>, env: Env): Promise<void> {
  for (const msg of batch.messages) {
    const ok = await reserveWrites(env.DB_CONTROL, msg.body.rows, msg.body.priority);
    if (!ok) {
      // First-load budget used up for today: try again after midnight UTC.
      msg.retry({ delaySeconds: Math.min(MAX_QUEUE_DELAY_SECONDS, secondsUntilUtcMidnight()) });
      continue;
    }
    // TODO(M1): read chunk from R2, build multi-row upserts (@ti/db upsertNewerSql), db.batch(), delete chunk.
    msg.ack();
  }
}
