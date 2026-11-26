import { describe, expect, it } from 'vitest';
import { ECOSYSTEMS, type Ecosystem } from '../packages';
import { compareDigits, compareInvalid, isSafeVersion, MAX_VERSION_LENGTH } from './common';
import { mustComparer } from './test-support';

const REJECTED: unknown[] = [
  '',
  'a'.repeat(129),
  '1.0.0\n',
  '1.0.0\u0000',
  '\u007f',
  ' 1.0.0',
  '1.0.0\t',
  '１.２.３',
  '1.0.0é',
  '1.0‮',
  undefined,
  null,
  1,
  {},
];

describe('common', () => {
  it('isSafeVersion: printable ASCII, 1 to 128 characters', () => {
    expect(isSafeVersion('1.0.0')).toBe(true);
    expect(isSafeVersion('!~')).toBe(true);
    expect(isSafeVersion('1'.repeat(MAX_VERSION_LENGTH))).toBe(true);
    expect(isSafeVersion('1'.repeat(MAX_VERSION_LENGTH + 1))).toBe(false);
    for (const v of ['', ' ', 'a b', '\u0080', 'é', '\ud800', undefined, null, 5, {}])
      expect(isSafeVersion(v)).toBe(false);
  });
  it('compareDigits compares whole numbers of any size', () => {
    expect(compareDigits('9', '10')).toBe(-1);
    expect(compareDigits('007', '7')).toBe(0);
    expect(compareDigits('', '0')).toBe(0);
    expect(compareDigits('', '1')).toBe(-1);
    expect(compareDigits('999999999999999999999999999999', '999999999999999999999999999998')).toBe(1);
    expect(compareDigits('123456789012345678901234567890', '123456789012345678901234567891')).toBe(-1);
  });
  it('compareInvalid: invalid sorts below valid, two invalid by code unit', () => {
    expect(compareInvalid('z', false, '0', true)).toBe(-1);
    expect(compareInvalid('0', true, 'z', false)).toBe(1);
    expect(compareInvalid('a', false, 'b', false)).toBe(-1);
    expect(compareInvalid('a', false, 'a', false)).toBe(0);
  });
});

describe('valid() rejects absurd input for every comparer', () => {
  for (const e of ECOSYSTEMS) {
    it(e, () => {
      const c = mustComparer(e);
      for (const bad of REJECTED) expect(c.valid(bad as string)).toBe(false);
    });
  }

  it('a 1,000,000-character string returns false in under 1 ms on average', () => {
    const huge = '1'.repeat(1_000_000);
    for (const e of ECOSYSTEMS) {
      const c = mustComparer(e);
      const start = performance.now();
      for (let i = 0; i < 1000; i++) c.valid(huge);
      expect((performance.now() - start) / 1000).toBeLessThan(1);
      expect(c.valid(huge)).toBe(false);
    }
  });
});

describe('per-ecosystem accept and reject lists', () => {
  const check = (e: Ecosystem, accept: string[], reject: string[]) => {
    const c = mustComparer(e);
    for (const v of accept) expect(c.valid(v), `${e} accepts ${v}`).toBe(true);
    for (const v of reject) expect(c.valid(v), `${e} rejects ${v}`).toBe(false);
  };
  it('semver family', () => {
    for (const e of ['npm', 'crates.io', 'Hex', 'SwiftURL'] as const) {
      check(
        e,
        ['v1.2.3-rc.1+b.5', '1', '1.2', '1.2.3-5-Foo'],
        ['V1.2.3', '1.2.3-', '1.2.3+', '1..2', 'latest'],
      );
    }
  });
  it('Go', () => {
    check(
      'Go',
      ['v0.0.0-20191109021931-daa7c04131f5', 'v2.0.0+incompatible', '0.52.0', 'v1', 'v1.2'],
      ['go1.21.3', 'master', 'V1.0.0'],
    );
  });
  it('GitHub Actions', () => {
    check(
      'GitHub Actions',
      ['v4', 'v4.1.0', '46.0.1'],
      ['1'.repeat(40), 'a5ac7e51b41094c92402da3b24376905380afc29'],
    );
  });
  it('Pub and NuGet', () => {
    check('Pub', ['1.0.0+build'], ['1.0.0+']);
    check('NuGet', ['1.0', '1.2.3.4', '1.0.0-BETA'], ['1.2.3.4.5', 'v1.0.0', '1.0.0-']);
  });
  it('PyPI', () => {
    check('PyPI', ['1!2.0.post1.dev3+local.7', '1.0', 'v1.0', '1.0RC1'], ['1.0-', '1.0.*', '0.1-bulbasaur']);
  });
  it('Maven', () => {
    check('Maven', ['r09', '1.0-SNAPSHOT', '1.0.0'], ['RELEASE', '1.0 beta', '1.0/2']);
  });
  it('Packagist', () => {
    check('Packagist', ['1.0.0', 'v1.2.3-beta1'], ['dev-main', 'master']);
  });
  it('Debian and Ubuntu', () => {
    for (const e of ['Debian', 'Ubuntu'] as const) {
      check(
        e,
        ['1:1.43.12+dfsg-1~deb13u1', '3.0.2-7ubuntu2.14'],
        ['1.2.3-not-a-debian:version!@#$', 'a1.0', ':1.0'],
      );
    }
  });
  it('Alpine and Red Hat', () => {
    check('Alpine', ['1.2.3-r0', '1.2_rc1', '1.2.3b'], ['.1', '1-ruff']);
    check('Red Hat', ['1:1.0-1.el8', '1.0~rc1'], []);
  });
  it('RubyGems', () => {
    check('RubyGems', ['1.0.0.pre', '1.0.0-beta'], ['a1', '1..0']);
  });
});
