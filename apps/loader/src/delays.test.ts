import { describe, expect, it } from 'vitest';
import { deferDelaySeconds, LOADER_MAX_RETRIES, retryDelaySeconds } from './delays';

describe('deferDelaySeconds', () => {
  it('reaches just past the next UTC midnight, at most 24 h', () => {
    expect(deferDelaySeconds(new Date('2026-11-23T23:59:30Z'))).toBe(90);
    expect(deferDelaySeconds(new Date('2026-11-23T12:00:00Z'))).toBe(43_260);
    expect(deferDelaySeconds(new Date('2026-11-24T00:00:00Z'))).toBe(86_400);
  });
});

describe('retryDelaySeconds', () => {
  it('doubles from 30 s and stops at an hour', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 8, 11].map(retryDelaySeconds)).toEqual([
      30, 60, 120, 240, 480, 960, 1920, 3600, 3600,
    ]);
    expect(retryDelaySeconds(1000)).toBe(3600);
  });
  it('matches max_retries in wrangler.jsonc', () => {
    expect(LOADER_MAX_RETRIES).toBe(10);
  });
});
