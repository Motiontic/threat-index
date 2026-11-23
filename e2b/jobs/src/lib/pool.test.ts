import { describe, expect, it } from 'vitest';
import { mapLimited, rateGate } from './pool.ts';

const tick = () => new Promise<void>((r) => setTimeout(r, 1));

describe('mapLimited', () => {
  it('keeps input order and never exceeds the limit', async () => {
    let now = 0;
    let peak = 0;
    const out = await mapLimited([5, 1, 4, 2, 3, 9, 8], 3, async (n, i) => {
      now++;
      peak = Math.max(peak, now);
      await tick();
      await new Promise<void>((r) => setTimeout(r, n));
      now--;
      return `${i}:${n}`;
    });
    expect(out).toEqual(['0:5', '1:1', '2:4', '3:2', '4:3', '5:9', '6:8']);
    expect(peak).toBe(3);
  });

  it('rejects on the first failure and starts no new work', async () => {
    const started: number[] = [];
    await expect(
      mapLimited([0, 1, 2, 3, 4, 5, 6, 7], 2, async (n) => {
        started.push(n);
        await tick();
        if (n === 1) throw new Error('boom');
        await new Promise<void>((r) => setTimeout(r, 20));
      }),
    ).rejects.toThrow('boom');
    await new Promise<void>((r) => setTimeout(r, 60));
    expect(started.length).toBeLessThan(8);
    expect(started).not.toContain(7);
  });

  it('handles no items', async () => {
    expect(await mapLimited([], 4, async () => 1)).toEqual([]);
  });
});

describe('rateGate', () => {
  it('spaces calls with a fake clock, also when called in parallel', async () => {
    let clock = 1_000_000;
    const slept: number[] = [];
    const gate = rateGate(
      10,
      async (ms) => {
        slept.push(ms);
        clock += ms;
      },
      () => new Date(clock),
    );
    await gate(); // slot now
    await gate(); // +100
    await gate(); // +200
    expect(slept).toEqual([100, 100]);
    clock += 1000;
    await gate(); // an idle gate does not wait
    expect(slept).toEqual([100, 100]);

    const waits: number[] = [];
    const parallel = rateGate(
      10,
      async (ms) => {
        waits.push(ms);
      },
      () => new Date(clock),
    );
    await Promise.all([parallel(), parallel(), parallel(), parallel()]);
    expect(waits).toEqual([100, 200, 300]);
  });
});
