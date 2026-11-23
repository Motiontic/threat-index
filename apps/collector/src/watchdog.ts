import type { Env } from './env';

/** Daily health check (§5): stale sources, unknown fields, queue depth. UNWIRED STUB: nothing calls this yet (no daily cron or queue path reaches it). M0 wires it in. */
export async function watchdog(_env: Env): Promise<void> {
  // TODO(M0): watchdog on the daily cron (§5).
}
