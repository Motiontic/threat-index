import { describe, expect, it } from 'vitest';
import { ECOSYSTEMS, type Ecosystem } from '../packages';
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

describe('comparerFor', () => {
  it('has a comparer for every ecosystem', () => {
    for (const e of ECOSYSTEMS) expect(comparerFor(e)).not.toBeNull();
  });
  it('is null for unknown names, including Object.prototype members', () => {
    for (const name of ['CRAN', 'constructor', '__proto__', 'toString', 'hasOwnProperty', '']) {
      expect(comparerFor(name as Ecosystem)).toBeNull();
    }
  });
  it('maps OS ecosystem keys that carry a release', () => {
    expect(comparerFor('Debian:12' as Ecosystem)).toBe(comparerFor('Debian'));
    expect(comparerFor('Ubuntu:22.04:LTS' as Ecosystem)).toBe(comparerFor('Ubuntu'));
    expect(comparerFor('Ubuntu:22.04:LTS' as Ecosystem)).toBe(comparerFor('Debian'));
    expect(comparerFor('Alpine:v3.20' as Ecosystem)).toBe(comparerFor('Alpine'));
    expect(comparerFor('Debian:12' as Ecosystem)?.compare('1:0.9', '2.0')).toBe(1);
    expect(comparerFor('Alpine:v3.20' as Ecosystem)?.compare('1.2_rc1', '1.2')).toBe(-1);
    expect(comparerFor('Red Hat:9' as Ecosystem)).toBeNull();
    expect(comparerFor('Debian' as Ecosystem)).not.toBeNull();
    expect(comparerFor(undefined as unknown as Ecosystem)).toBeNull();
  });
});

describe('inRange with the real comparers', () => {
  it('PyPI [0, 1.3.0)', () => {
    const r = row({ fixed: '1.3.0' });
    expect(inRange('PyPI', '1.2.0', r)).toBe(true);
    expect(inRange('PyPI', '1.3.0rc1', r)).toBe(true);
    expect(inRange('PyPI', '1.3.0', r)).toBe(false);
    expect(inRange('PyPI', '1.3.0.post1', r)).toBe(false);
  });
  it('Maven [2.13.0, 2.15.0) and [2.0-beta9, 2.3.1)', () => {
    const r = row({ introduced: '2.13.0', fixed: '2.15.0' });
    expect(inRange('Maven', '2.14.1', r)).toBe(true);
    expect(inRange('Maven', '2.15.0', r)).toBe(false);
    const q = row({ introduced: '2.0-beta9', fixed: '2.3.1' });
    expect(inRange('Maven', '2.0-rc1', q)).toBe(true);
    expect(inRange('Maven', '2.0-beta8', q)).toBe(false);
  });
  it('Go SEMVER [0, 0.52.0)', () => {
    const r = row({ range_type: 'SEMVER', fixed: '0.52.0' });
    expect(inRange('Go', 'v0.51.0', r)).toBe(true);
    expect(inRange('Go', 'v0.0.0-20240101000000-abcdefabcdef', r)).toBe(true);
    expect(inRange('Go', 'v0.52.0', r)).toBe(false);
  });
  it('Debian and Ubuntu', () => {
    const d = row({ fixed: '1:1.43.12+dfsg-1~deb13u1' });
    expect(inRange('Debian', '1:1.43.11+dfsg-2', d)).toBe(true);
    expect(inRange('Debian', '1:1.43.12+dfsg-1~deb13u1', d)).toBe(false);
    expect(inRange('Debian', '1:1.43.12+dfsg-1', d)).toBe(false);
    expect(inRange('Ubuntu', '3.0.2-7ubuntu2.13', row({ fixed: '3.0.2-7ubuntu2.14' }))).toBe(true);
  });
  it('npm [1.0.0, last_affected 1.2.0]', () => {
    const r = row({ introduced: '1.0.0', last_affected: '1.2.0' });
    expect(inRange('npm', '1.2.0', r)).toBe(true);
    expect(inRange('npm', '1.2.1', r)).toBe(false);
    expect(inRange('npm', '0.9.0', r)).toBe(false);
  });
  it('an open-ended row matches any version for any ecosystem name, with no comparer', () => {
    for (const range_type of ['SEMVER', 'ECOSYSTEM'] as const) {
      for (const e of [...ECOSYSTEMS, 'CRAN' as Ecosystem]) {
        expect(inRange(e, '35.7.4', row({ range_type }))).toBe(true);
        expect(inRange(e, 'not a version', row({ range_type }))).toBe(true);
      }
    }
  });
  it('an EXACT row with introduced "0" still matches only its listed versions', () => {
    const r = row({ range_type: 'EXACT', introduced: '0', versions: '["1.0.0"]' });
    expect(inRange('npm', '1.0.0', r)).toBe(true);
    expect(inRange('npm', '2.0.0', r)).toBe(false);
    expect(inRange('CRAN' as Ecosystem, 'not a version', r)).toBe(false);
  });
  it('a ranged row with an unparseable version or bound is unsupported', () => {
    expect(inRange('npm', 'latest', row({ fixed: '2.0.0' }))).toBe('unsupported');
    expect(inRange('npm', '1.0.0', row({ fixed: 'x.y' }))).toBe('unsupported');
    expect(inRange('npm', '1.0.0', row({ introduced: 'x.y', fixed: '2.0.0' }))).toBe('unsupported');
    expect(inRange('npm', '1.0.0', row({ last_affected: '' }))).toBe('unsupported');
    expect(inRange('CRAN' as Ecosystem, '1.0.0', row({ fixed: '2.0.0' }))).toBe('unsupported');
  });
});
