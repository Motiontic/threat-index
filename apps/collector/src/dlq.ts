import { decodeTime } from 'ulid';
import type { Env } from './env';
import { parseJobMessage } from './env';

/** `max_retries` (5) of the ti-jobs consumer in wrangler.jsonc, plus the first attempt. */
export const JOBS_MAX_ATTEMPTS = 6;

export interface DlqDeps {
  now(): Date;
  log(msg: string, extra?: Record<string, unknown>): void;
}

/**
 * Consumes ti-jobs-dlq: a step that ran out of retries has its run marked `failed` (with the error the
 * last attempt stored), or gets a `failed` row if it never wrote one. Finished runs are left alone.
 * Invalid bodies are acked; a D1 error retries the message.
 */
export async function recordDeadLetters(
  batch: MessageBatch<unknown>,
  env: Pick<Env, 'DB_CONTROL'>,
  deps: DlqDeps,
): Promise<void> {
  const prefix = `dead-lettered after ${JOBS_MAX_ATTEMPTS} attempts: `;
  for (const msg of batch.messages) {
    const job = parseJobMessage(msg.body);
    if (!job) {
      deps.log('dead letter with an invalid body', { queue: batch.queue });
      msg.ack();
      continue;
    }
    try {
      const at = deps.now().toISOString();
      const res = await env.DB_CONTROL.prepare(
        `INSERT INTO runs (id, source_id, started_at, finished_at, status, error)
         VALUES (?1, ?2, ?3, ?4, 'failed', ?5 || 'none')
         ON CONFLICT(id) DO UPDATE SET status = 'failed', finished_at = excluded.finished_at,
           error = substr(?5 || COALESCE(runs.error, 'none'), 1, 500)
         WHERE runs.status = 'running'`,
      )
        .bind(job.runId, job.sourceId, new Date(decodeTime(job.runId)).toISOString(), at, prefix)
        .run();
      deps.log('dead letter recorded', {
        sourceId: job.sourceId,
        runId: job.runId,
        step: job.step,
        changed: res.meta.changes ?? 0,
      });
      msg.ack();
    } catch (err) {
      deps.log('dead letter not recorded', { runId: job.runId, error: String((err as Error)?.name) });
      msg.retry({ delaySeconds: 60 });
    }
  }
}
