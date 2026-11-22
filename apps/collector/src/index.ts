import { canIngest } from '@ti/core';
import { SOURCES, type SourceConfig } from '@ti/sources';

/**
 * ti-collector. See docs/IMPLEMENTATION_PLAN.md §5.
 * scheduled(): pick the sources that are due and queue one job each.
 * queue(): run one small step per message (≤ 40 records), then queue the next step if needed.
 */
export interface Env {
  DB_CONTROL: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_SIGNALS: D1Database;
  DB_WORLD: D1Database;
  BUCKET: R2Bucket;
  SETTINGS: KVNamespace;
  JOBS: Queue<JobMessage>;
  NOTIFY: Queue<{ kind: 'run-finished'; at: number }>;
  USER_AGENT: string;
}

export interface JobMessage {
  sourceId: string;
  runId: string;
  step: number;
}

const CADENCE_BY_CRON: Record<string, SourceConfig['cadence'][]> = {
  '0 */3 * * *': ['3h', 'with-cve-list'],
  '45 14 * * *': ['daily'],
  '30 2 * * *': [], // nightly fold + search index: E2B jobs (M1)
  '0 5 * * 1': ['weekly', 'monthly', 'quarterly'],
};

function dueSources(cron: string): SourceConfig[] {
  const cadences = CADENCE_BY_CRON[cron] ?? [];
  return SOURCES.filter((s) => cadences.includes(s.cadence) && canIngest(s.licence));
}

export default {
  async scheduled(event: ScheduledController, env: Env): Promise<void> {
    const due = dueSources(event.cron);
    const runId = `${Date.now().toString(36)}`;
    for (let i = 0; i < due.length; i += 100) {
      await env.JOBS.sendBatch(
        due.slice(i, i + 100).map((s) => ({ body: { sourceId: s.id, runId, step: 0 } })),
      );
    }
    if (event.cron === '0 */3 * * *') await env.NOTIFY.send({ kind: 'run-finished', at: Date.now() });
    // TODO(M0): watchdog on the daily cron (§5).
  },

  async queue(batch: MessageBatch<JobMessage>, _env: Env): Promise<void> {
    for (const msg of batch.messages) {
      try {
        // TODO(M1): load cursor → pattern.check() → pattern.fetch() → receipt to R2 raw/
        //           → parse (≤ 40) → linker → D1 upserts (counted) → commit cursor → continue if `more`.
        msg.ack();
      } catch {
        msg.retry({ delaySeconds: Math.min(3600, 30 * 2 ** msg.attempts) });
      }
    }
  },
} satisfies ExportedHandler<Env, JobMessage>;
