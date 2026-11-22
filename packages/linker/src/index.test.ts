import { describe, expect, it } from 'vitest';
import { detectChanges, epssBand, isHot } from './index';

describe('hot set', () => {
  it('keeps recent, exploited, exploit-public and high-EPSS flaws hot', () => {
    expect(isHot({ published: '2025-04-07' })).toBe(true);
    expect(isHot({ published: '2021-12-10', kevAdded: '2021-12-10' })).toBe(true);
    expect(isHot({ published: '2019-01-01', epss: 0.12 })).toBe(true);
    expect(isHot({ published: '2019-01-01', epss: 0.02 })).toBe(false);
  });
});

describe('change detection', () => {
  it('flags newly exploited and EPSS band jumps, nothing else', () => {
    const changes = detectChanges(
      { key: 'CVE-2025-3248', epss: 0.08 },
      { key: 'CVE-2025-3248', kevAdded: '2025-05-05', epss: 0.94 },
    );
    expect(changes.map((c) => c.kind)).toEqual(['newly_exploited', 'epss_band']);
    expect(epssBand(0.94)).toBe(3);
  });
});
