import type { Env } from './env';

/** Daily health check (§5): stale sources, unknown fields, queue depth. Stub until M0 lands it. */
export async function watchdog(_env: Env): Promise<void> {
  // TODO(M0): watchdog on the daily cron (§5).
}
