import { describe, expect, it } from 'vitest';
import { benchPairs, expectedSign, mustComparer } from './test-support';

describe('bench pairs', () => {
  it('every item gives its expected answer', () => {
    const pairs = benchPairs();
    expect(pairs).toHaveLength(10_000);
    const wrong = pairs.filter((p) => mustComparer(p.ecosystem).compare(p.a, p.b) !== expectedSign(p.op));
    expect(wrong.slice(0, 5)).toEqual([]);
  });
  it('covers all 16 ecosystems', () => {
    expect(new Set(benchPairs().map((p) => p.ecosystem)).size).toBe(16);
  });
});
