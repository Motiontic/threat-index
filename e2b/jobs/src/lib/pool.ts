/** Small concurrency helpers for the sandbox jobs. */

/**
 * Maps `items` with at most `limit` calls in flight. Results come back in input order. The first rejection
 * rejects the whole call and no new work starts after it (calls already running finish on their own).
 */
export async function mapLimited<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, i: number) => Promise<R>,
): Promise<R[]> {
  if (!Number.isInteger(limit) || limit < 1) throw new Error('mapLimited needs a limit of at least 1');
  const out = new Array<R>(items.length);
  let next = 0;
  let failed = false;
  const worker = async (): Promise<void> => {
    while (!failed && next < items.length) {
      const i = next++;
      try {
        out[i] = await fn(items[i] as T, i);
      } catch (err) {
        failed = true;
        throw err;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/**
 * A gate that spaces callers `1000 / perSecond` ms apart. `await gate()` before each request. Slots are taken
 * synchronously, so callers running in parallel are still spaced out.
 */
export function rateGate(
  perSecond: number,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise<void>((r) => setTimeout(r, ms)),
  now: () => Date = () => new Date(),
): () => Promise<void> {
  const interval = 1000 / perSecond;
  let next = Number.NEGATIVE_INFINITY;
  return async () => {
    const t = now().getTime();
    const slot = Math.max(next, t);
    next = slot + interval;
    if (slot > t) await sleep(slot - t);
  };
}
