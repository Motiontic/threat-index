import { describe, expect, it } from 'vitest';
import { SOURCES } from './registry';

describe('source registry', () => {
  it('has 55 sources with unique ids', () => {
    expect(SOURCES).toHaveLength(55);
    expect(new Set(SOURCES.map((s) => s.id)).size).toBe(55);
  });

  it('matches the licence split: 24 on, 23 ask, 6 wait, 2 link', () => {
    const count = (l: string) => SOURCES.filter((s) => s.licence === l).length;
    expect([count('on'), count('ask'), count('wait'), count('link')]).toEqual([24, 23, 6, 2]);
  });
});
