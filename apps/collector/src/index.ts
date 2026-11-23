import type { Env, JobMessage } from './env';
import { plan } from './planner';
import { runStep } from './step';

/**
 * ti-collector. See docs/IMPLEMENTATION_PLAN.md §5. This file only wires events to modules:
 * scheduled() → planner.ts, queue() → step.ts (backoff.ts is used from there).
 * watchdog.ts is an unwired stub: nothing calls it yet.
 */
export type { Env, JobMessage } from './env';

export default {
  async scheduled(event: ScheduledController, env: Env): Promise<void> {
    await plan(event, env);
  },

  async queue(batch: MessageBatch<JobMessage>, env: Env): Promise<void> {
    for (const msg of batch.messages) await runStep(msg, env);
  },
} satisfies ExportedHandler<Env, JobMessage>;
