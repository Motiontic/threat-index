import { consume, type Env, type NotifyMessage } from './consume';

/** ti-notify. See docs/IMPLEMENTATION_PLAN.md §10. This file only wires queue() to consume.ts. */
export type { Env } from './consume';

export default {
  async queue(batch: MessageBatch<NotifyMessage>, env: Env): Promise<void> {
    await consume(batch, env);
  },
} satisfies ExportedHandler<Env, NotifyMessage>;
