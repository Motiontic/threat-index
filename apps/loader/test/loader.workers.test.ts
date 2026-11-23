import { env } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import worker from '../src/index';

it('queue() acks an empty batch', async () => {
  let retried = false;
  const batch = {
    queue: 'ti-load-staging',
    messages: [],
    ackAll: () => {},
    retryAll: () => {
      retried = true;
    },
  } as unknown as MessageBatch<never>;
  await expect(worker.queue(batch, env as never)).resolves.toBeUndefined();
  // Nothing to ack or retry: the batch is done, not sent back to the queue.
  expect(retried).toBe(false);
});
