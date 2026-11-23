import { consume, type Env, type LoadMessage } from './consume';

/** ti-loader. See docs/IMPLEMENTATION_PLAN.md §7. This file only wires queue() to consume.ts. */
export type { Env, LoadMessage } from './consume';

export default {
  async queue(batch: MessageBatch<LoadMessage>, env: Env): Promise<void> {
    await consume(batch, env);
  },
} satisfies ExportedHandler<Env, LoadMessage>;
