import { env } from 'cloudflare:workers';
import {
  budgetUsage,
  D1_DAILY_WRITE_LIMIT,
  FIRST_LOAD_DAILY_CAP,
  releaseWrites,
  reserveWrites,
} from '@ti/core/budget';
import { beforeEach, describe, expect, it } from 'vitest';

const db = env.DB_CONTROL;
const NOW = new Date('2026-11-23T12:00:00Z');
const meter = async (day = '2026-11-23') =>
  (await db.prepare('SELECT d1_writes AS n FROM budget WHERE day = ?1').bind(day).first<{ n: number }>())?.n;

beforeEach(async () => {
  await db.prepare('DELETE FROM budget').run();
});

describe('reserveWrites', () => {
  it('first-load: 90,000 exactly passes and one more does not', async () => {
    expect(await reserveWrites(db, FIRST_LOAD_DAILY_CAP - 1, 'first-load', NOW)).toBe(true);
    expect(await reserveWrites(db, 1, 'first-load', NOW)).toBe(true);
    expect(await meter()).toBe(FIRST_LOAD_DAILY_CAP);
    expect(await reserveWrites(db, 1, 'first-load', NOW)).toBe(false);
    expect(await meter()).toBe(FIRST_LOAD_DAILY_CAP);
  });
  it('first-load: a single reservation of exactly the cap passes on an empty day', async () => {
    expect(await reserveWrites(db, FIRST_LOAD_DAILY_CAP, 'first-load', NOW)).toBe(true);
  });
  it('steady is never blocked and is counted', async () => {
    await reserveWrites(db, FIRST_LOAD_DAILY_CAP, 'first-load', NOW);
    expect(await reserveWrites(db, 60_000, 'steady', NOW)).toBe(true);
    expect(await meter()).toBe(150_000);
  });
  it('steady creates the day row in one statement', async () => {
    expect(await reserveWrites(db, 7, 'steady', NOW)).toBe(true);
    expect(await meter()).toBe(7);
  });
  it('20 parallel first-load reservations never pass the cap', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, () => reserveWrites(db, 5_000, 'first-load', NOW)),
    );
    expect(results.filter(Boolean).length).toBe(18);
    expect(await meter()).toBe(FIRST_LOAD_DAILY_CAP);
  });
  it('each UTC day has its own meter', async () => {
    await reserveWrites(db, 10, 'steady', NOW);
    await reserveWrites(db, 5, 'steady', new Date('2026-11-24T00:00:00Z'));
    expect(await meter('2026-11-23')).toBe(10);
    expect(await meter('2026-11-24')).toBe(5);
  });
  it('rejects bad n and writes nothing', async () => {
    for (const n of [-1, 1.5, Number.NaN, 2 ** 53])
      await expect(reserveWrites(db, n, 'steady', NOW)).rejects.toBeInstanceOf(RangeError);
    await expect(reserveWrites(db, FIRST_LOAD_DAILY_CAP + 1, 'first-load', NOW)).rejects.toBeInstanceOf(
      RangeError,
    );
    expect(await meter()).toBeUndefined();
  });
  it('n = 0 returns true and creates no row', async () => {
    expect(await reserveWrites(db, 0, 'first-load', NOW)).toBe(true);
    expect(await meter()).toBeUndefined();
  });
});

describe('releaseWrites', () => {
  it('subtracts and stops at 0', async () => {
    await reserveWrites(db, 100, 'steady', NOW);
    await releaseWrites(db, 30, NOW);
    expect(await meter()).toBe(70);
    await releaseWrites(db, 1_000, NOW);
    expect(await meter()).toBe(0);
  });
  it('does nothing without a row, and rejects bad n', async () => {
    await releaseWrites(db, 5, NOW);
    expect(await meter()).toBeUndefined();
    await expect(releaseWrites(db, -1, NOW)).rejects.toBeInstanceOf(RangeError);
  });
});

describe('budgetUsage', () => {
  it('is zeros when today has no row', async () => {
    expect(await budgetUsage(db, NOW)).toEqual({
      day: '2026-11-23',
      d1Writes: 0,
      firstLoadCap: FIRST_LOAD_DAILY_CAP,
      dailyLimit: D1_DAILY_WRITE_LIMIT,
      firstLoadRemaining: FIRST_LOAD_DAILY_CAP,
    });
    expect(await meter()).toBeUndefined(); // read only
  });
  it('reports today, and never a negative remainder', async () => {
    await reserveWrites(db, 25_000, 'steady', NOW);
    expect((await budgetUsage(db, NOW)).firstLoadRemaining).toBe(65_000);
    await reserveWrites(db, 100_000, 'steady', NOW);
    const u = await budgetUsage(db, NOW);
    expect(u.d1Writes).toBe(125_000);
    expect(u.firstLoadRemaining).toBe(0);
  });
});
