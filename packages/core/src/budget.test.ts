import { describe, expect, it } from 'vitest';
import {
  FIRST_LOAD_DAILY_CAP,
  releaseWrites,
  reserveWrites,
  secondsUntilUtcMidnight,
  utcDay,
} from './budget';

/** A D1 stub that fails the test if any query is prepared. */
const noQueries = {
  prepare() {
    throw new Error('unexpected query');
  },
} as unknown as D1Database;

describe('budget argument checks (no D1 needed)', () => {
  it('n = 0 returns true with no query', async () => {
    expect(await reserveWrites(noQueries, 0, 'steady')).toBe(true);
    expect(await reserveWrites(noQueries, 0, 'first-load')).toBe(true);
    await releaseWrites(noQueries, 0);
  });
  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53])('rejects n = %s', async (n) => {
    await expect(reserveWrites(noQueries, n, 'steady')).rejects.toBeInstanceOf(RangeError);
    await expect(releaseWrites(noQueries, n)).rejects.toBeInstanceOf(RangeError);
  });
  it('rejects a first-load n above the cap, but not a steady one', async () => {
    await expect(reserveWrites(noQueries, FIRST_LOAD_DAILY_CAP + 1, 'first-load')).rejects.toBeInstanceOf(
      RangeError,
    );
  });
});

describe('utc helpers', () => {
  it('utcDay and secondsUntilUtcMidnight', () => {
    expect(utcDay(new Date('2026-11-23T23:59:59Z'))).toBe('2026-11-23');
    expect(secondsUntilUtcMidnight(new Date('2026-11-23T23:59:30Z'))).toBe(30);
    expect(secondsUntilUtcMidnight(new Date('2026-11-24T00:00:00Z'))).toBe(86_400);
  });
});
