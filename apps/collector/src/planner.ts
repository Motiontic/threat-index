import { canIngest } from '@ti/core/licence';
import { SOURCES, type SourceConfig } from '@ti/sources/registry';
import type { Env } from './env';

export const CADENCE_BY_CRON: Record<string, SourceConfig['cadence'][]> = {
  '0 */3 * * *': ['3h', 'with-cve-list'],
  '45 14 * * *': ['daily'],
  '30 2 * * *': [], // nightly fold + search index: E2B jobs (M1)
  '0 5 * * 1': ['weekly', 'monthly', 'quarterly'],
};

export function dueSources(cron: string): SourceConfig[] {
  const cadences = CADENCE_BY_CRON[cron] ?? [];
  return SOURCES.filter((s) => cadences.includes(s.cadence) && canIngest(s.licence));
}

/** Queues one job per due source, then tells ti-notify when the 3-hourly run has been queued. */
export async function plan(event: ScheduledController, env: Env): Promise<void> {
  const due = dueSources(event.cron);
  const runId = `${Date.now().toString(36)}`;
  for (let i = 0; i < due.length; i += 100) {
    await env.JOBS.sendBatch(
      due.slice(i, i + 100).map((s) => ({ body: { sourceId: s.id, runId, step: 0 } })),
    );
  }
  if (event.cron === '0 */3 * * *') await env.NOTIFY.send({ kind: 'run-finished', at: Date.now() });
}
