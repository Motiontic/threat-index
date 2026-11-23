import { inboxChunkKey, type LoadMessage, MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import { RowValidationError, WriteLimitError } from '@ti/db/plan';
import { databasesFromEnv, writeRows } from '@ti/db/write';
import { CorruptChunkError, readChunk } from './chunk';
import { deferDelaySeconds, LOADER_MAX_RETRIES, retryDelaySeconds } from './delays';
import { recordLoadFailure } from './failure';

/** ti-loader. See docs/IMPLEMENTATION_PLAN.md §7. One message = one inbox chunk (≤ 500 rows). */
export interface Env {
  DB_CONTROL: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_SIGNALS: D1Database;
  DB_WORLD: D1Database;
  BUCKET: R2Bucket;
  LOAD: Queue<LoadMessage>;
}

const JOB_ID = /^[A-Za-z0-9_-]{1,64}$/;
const CHUNK_KEY = /^inbox\/[^/]+\/(0|[1-9][0-9]*)\.ndjson\.gz$/;

/** One JSON object per line. Never put row contents in `fields`. */
function log(event: string, fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ event, ...fields }));
}

/** Returns the checked body, or undefined. A bad body must never lead to an R2 access. */
function checkBody(body: unknown): LoadMessage | undefined {
  if (typeof body !== 'object' || body === null) return undefined;
  const { jobId, chunkKey, rows, priority } = body as Record<string, unknown>;
  if (typeof jobId !== 'string' || !JOB_ID.test(jobId)) return undefined;
  if (typeof chunkKey !== 'string') return undefined;
  const m = CHUNK_KEY.exec(chunkKey);
  if (!m || chunkKey !== inboxChunkKey(jobId, Number(m[1]))) return undefined;
  if (!Number.isInteger(rows) || (rows as number) < 1 || (rows as number) > MAX_ROWS_PER_CHUNK)
    return undefined;
  if (priority !== 'steady' && priority !== 'first-load') return undefined;
  return { jobId, chunkKey, rows: rows as number, priority };
}

/** Errors that no retry will fix: the chunk or its rows are bad. */
function corruptReason(err: unknown): string | undefined {
  if (err instanceof CorruptChunkError || err instanceof RowValidationError || err instanceof WriteLimitError)
    return err.message;
  const text = err instanceof Error ? err.message : '';
  const at = text.indexOf('constraint failed');
  // SQLite names the constraint, never the value.
  if (at !== -1) return text.slice(Math.max(0, at - 12), at + 200);
  return undefined;
}

export async function consume(batch: MessageBatch<LoadMessage>, env: Env): Promise<void> {
  for (const msg of batch.messages) {
    await consumeOne(msg, env);
  }
}

async function consumeOne(msg: Message<LoadMessage>, env: Env): Promise<void> {
  const body = checkBody(msg.body);
  if (!body) {
    log('load_bad_message', { reason: 'body failed validation' });
    msg.ack();
    return;
  }
  const { jobId, chunkKey, priority } = body;
  const now = new Date();
  try {
    const object = await env.BUCKET.get(chunkKey);
    if (!object) {
      log('load_missing', { jobId, chunkKey });
      msg.ack();
      return;
    }
    const rows = await readChunk(object, body.rows);
    const result = await writeRows(databasesFromEnv(env as unknown as Record<string, unknown>), rows, {
      priority,
      now,
    });
    if (result.deferred) {
      // A fresh message, not msg.retry(): a first load lasts about two weeks, so retries would use up
      // max_retries and could outlive message retention.
      const delaySeconds = deferDelaySeconds(now);
      await env.LOAD.send(body, { delaySeconds });
      log('load_deferred', { jobId, chunkKey, rows: rows.length, delaySeconds });
      msg.ack();
      return;
    }
    await env.BUCKET.delete(chunkKey);
    log('load_ok', {
      jobId,
      chunkKey,
      rows: rows.length,
      written: result.written,
      statements: result.statements,
    });
    msg.ack();
  } catch (err) {
    await handleError(msg, env, body, err, now);
  }
}

async function handleError(
  msg: Message<LoadMessage>,
  env: Env,
  body: LoadMessage,
  err: unknown,
  now: Date,
): Promise<void> {
  const { jobId, chunkKey } = body;
  const corrupt = corruptReason(err);
  if (corrupt !== undefined) {
    try {
      await recordLoadFailure(env.DB_CONTROL, jobId, `${chunkKey}: ${corrupt}`, now);
      log('load_failed', { jobId, chunkKey, reason: corrupt });
      msg.ack(); // keep the chunk in R2 for inspection; no retry
      return;
    } catch (recordErr) {
      // Couldn't record it: fall through and retry, so the failure isn't lost.
      log('load_retry', { jobId, chunkKey, reason: 'could not record failure', error: String(recordErr) });
      msg.retry({ delaySeconds: retryDelaySeconds(msg.attempts) });
      return;
    }
  }
  const reason = err instanceof Error ? `${err.name}: ${err.message}` : 'unknown error';
  if (msg.attempts > LOADER_MAX_RETRIES) {
    // Last delivery and no dead-letter queue: after this the message is gone.
    try {
      await recordLoadFailure(
        env.DB_CONTROL,
        jobId,
        `${chunkKey}: gave up after ${msg.attempts} tries: ${reason}`,
        now,
      );
    } catch (recordErr) {
      log('load_failed', { jobId, chunkKey, reason: 'could not record failure', error: String(recordErr) });
    }
    log('load_failed', { jobId, chunkKey, reason: `gave up after ${msg.attempts} tries`, error: reason });
    msg.ack();
    return;
  }
  const delaySeconds = retryDelaySeconds(msg.attempts);
  log('load_retry', { jobId, chunkKey, attempts: msg.attempts, delaySeconds, error: reason });
  msg.retry({ delaySeconds });
}
