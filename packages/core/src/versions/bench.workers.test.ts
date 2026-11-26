import { describe, expect, it } from 'vitest';
import { benchPairs, expectedSign, mustComparer } from './test-support';

const CEILING_MS = 250;

describe('versions bench (Workers runtime)', () => {
  it('10,000 comparisons stay under the ceiling', () => {
    const pairs = benchPairs();
    const work = pairs.map((p) => ({
      cmp: mustComparer(p.ecosystem),
      a: p.a,
      b: p.b,
      want: expectedSign(p.op),
    }));
    const run = (): { ms: number; wrong: number } => {
      let wrong = 0;
      const start = performance.now();
      for (const w of work) if (w.cmp.compare(w.a, w.b) !== w.want) wrong++;
      return { ms: performance.now() - start, wrong };
    };
    run(); // warm up
    const runs = Array.from({ length: 5 }, run);
    expect(runs.reduce((n, r) => n + r.wrong, 0)).toBe(0);
    const times = runs.map((r) => r.ms).sort((x, y) => x - y);
    const median = times[2] as number;
    console.log(`versions bench: median ${median.toFixed(2)} ms for ${work.length} comparisons`);
    expect(
      times.some((t) => t > 0),
      "clock didn't advance",
    ).toBe(true);
    expect(median).toBeLessThan(CEILING_MS);
  });
});
