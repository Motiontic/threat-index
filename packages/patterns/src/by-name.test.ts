import type { PatternName } from '@ti/sources/registry';
import { SOURCES } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { patternFor } from './by-name';

// A Record forces this list to cover every PatternName at compile time.
const NAMES: Record<PatternName, true> = {
  git: true,
  changelist: true,
  since: true,
  fingerprint: true,
  feed: true,
  page: true,
  heavy: true,
};

describe('patternFor', () => {
  it.each(Object.keys(NAMES) as PatternName[])('resolves %s', (name) => {
    const mod = patternFor(name);
    expect(typeof mod.check).toBe('function');
    expect(typeof mod.fetch).toBe('function');
  });
  it('resolves the pattern of every registered source', () => {
    for (const s of SOURCES) expect(patternFor(s.pattern)).toBeDefined();
  });
});
