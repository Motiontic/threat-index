import { ulid } from 'ulid';
import { defaultDeps, logLine } from './deps';
import { recordDeadLetters } from './dlq';
import type { Env, JobMessage } from './env';
import { plan } from './planner';
import { runStep } from './step';
import { runWatchdog } from './watchdog';

/**
 * ti-collector. See docs/IMPLEMENTATION_PLAN.md §5. This file only wires events to modules:
 * scheduled() → planner.ts (and watchdog.ts on the daily cron), queue() → step.ts for ti-jobs and
 * dlq.ts for ti-jobs-dlq.
 */
export type { Env, JobMessage } from './env';

const WATCHDOG_CRON = '45 14 * * *';
const DLQ_QUEUE = /^ti-jobs-dlq(-staging)?$/;

export default {
  async scheduled(event: ScheduledController, env: Env): Promise<void> {
    const errors: unknown[] = [];
    try {
      await plan(event, env, { newId: ulid });
    } catch (err) {
      errors.push(err);
    }
    if (event.cron === WATCHDOG_CRON) {
      try {
        await runWatchdog(env, { now: () => new Date(event.scheduledTime), newId: ulid, log: logLine });
      } catch (err) {
        errors.push(err);
      }
    }
    if (errors.length > 0) throw errors[0];
  },

  async queue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
    if (DLQ_QUEUE.test(batch.queue)) {
      await recordDeadLetters(batch, env, { now: () => new Date(), log: logLine });
      return;
    }
    const deps = defaultDeps(env);
    for (const msg of batch.messages) {
      const out = await runStep(msg.body, msg.attempts, env, deps);
      if (out.ack) msg.ack();
      else msg.retry({ delaySeconds: out.delaySeconds });
    }
  },
} satisfies ExportedHandler<Env, JobMessage>;
