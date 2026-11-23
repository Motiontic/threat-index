import { retryDelaySeconds } from './backoff';
import type { Env, JobMessage } from './env';

/** Runs one queue message: one small step (≤ 40 records) for one source. */
export async function runStep(msg: Message<JobMessage>, _env: Env): Promise<void> {
  try {
    // TODO(M1): load cursor → pattern.check() → pattern.fetch() → receipt to R2 raw/
    //           → parse (≤ 40) → linker → D1 upserts (counted) → commit cursor → continue if `more`.
    msg.ack();
  } catch {
    msg.retry({ delaySeconds: retryDelaySeconds(msg.attempts) });
  }
}
