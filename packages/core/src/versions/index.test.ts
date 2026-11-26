import { describe, expect, it } from 'vitest';
import { ECOSYSTEMS } from '../packages';
import { type Comparer, comparerFor, inRange, type RangeRow } from './index';

/** Toy comparer: versions are non-negative integers. */
const toy: Comparer = {
  valid: (v) => /^\d+$/.test(v),
  compare: (a, b) => Number(a) - Number(b),
};
const row = (r: Partial<RangeRow>): RangeRow => ({
  range_type: 'ECOSYSTEM',
  introduced: '0',
  fixed: null,
  last_affected: null,
  versions: null,
  ...r,
});
const at = (v: string, r: Partial<RangeRow>) => inRange('npm', v, row(r), toy);

describe('inRange with a comparer', () => {
  it('"0" means from the start; fixed is exclusive', () => {
    expect(at('0', { fixed: '5' })).toBe(true);
    expect(at('4', { fixed: '5' })).toBe(true);
    expect(at('5', { fixed: '5' })).toBe(false);
    expect(at('9', { fixed: '5' })).toBe(false);
  });
  it('introduced is inclusive', () => {
    expect(at('2', { introduced: '3', fixed: '8' })).toBe(false);
    expect(at('3', { introduced: '3', fixed: '8' })).toBe(true);
    expect(at('7', { introduced: '3', fixed: '8' })).toBe(true);
  });
  it('last_affected is inclusive', () => {
    expect(at('6', { introduced: '3', last_affected: '6' })).toBe(true);
    expect(at('7', { introduced: '3', last_affected: '6' })).toBe(false);
  });
  it('with no upper bound, everything from introduced on is affected', () => {
    expect(at('1000', { introduced: '3' })).toBe(true);
    expect(at('1000', {})).toBe(true);
  });
  it('is unsupported when the version or a bound is not valid for the comparer', () => {
    expect(at('1.0', { fixed: '5' })).toBe('unsupported');
    expect(at('1', { fixed: 'x' })).toBe('unsupported');
    expect(at('1', { introduced: 'x' })).toBe('unsupported');
  });
  it('SEMVER rows use the comparer the same way', () => {
    expect(at('4', { range_type: 'SEMVER', introduced: '1', fixed: '5' })).toBe(true);
  });
});

describe('inRange, EXACT rows', () => {
  const exact = (versions: string | null) => row({ range_type: 'EXACT', versions });
  it('matches by string equality, with no comparer', () => {
    expect(inRange('Go', 'v1.2.3', exact('["v1.2.2","v1.2.3"]'))).toBe(true);
    expect(inRange('Go', 'v1.2.4', exact('["v1.2.2","v1.2.3"]'))).toBe(false);
    expect(inRange('Go', '1.2.3', exact('["v1.2.3"]'))).toBe(false);
  });
  it('is false for a missing or broken list', () => {
    expect(inRange('npm', '1', exact(null))).toBe(false);
    expect(inRange('npm', '1', exact('not json'))).toBe(false);
    expect(inRange('npm', '1', exact('{"a":1}'))).toBe(false);
  });
});

describe('today, no ecosystem has a comparer', () => {
  it('comparerFor is null and ranges are unsupported for every ecosystem', () => {
    for (const e of ECOSYSTEMS) {
      expect(comparerFor(e)).toBeNull();
      expect(inRange(e, '1.0.0', row({ fixed: '2.0.0' }))).toBe('unsupported');
      expect(inRange(e, '1.0.0', row({ range_type: 'SEMVER', fixed: '2.0.0' }))).toBe('unsupported');
    }
  });
});
