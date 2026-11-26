import { describe, expect, it } from 'vitest';
import { readCheckBody, validVersion } from '../src/lib/packages-input';

const one = (e: unknown, ok = true) => {
  const r = readCheckBody({ packages: [e] });
  if (!r.ok) throw new Error(r.error);
  return ok ? r : r;
};
const reason = (e: unknown) => one(e).rejected[0]?.reason;
const accepted = (e: unknown) => one(e).entries[0]?.ref;
const pkg = (ecosystem: string, name: string, version: string) => ({ ecosystem, name, version });

/** Deterministic pseudo-random text (mulberry32), one alphabet symbol per draw. */
const rnd = (alphabet: string, n: number, seed: number) => {
  let a = seed * 2654435761;
  let out = '';
  for (let i = 0; i < n; i++) {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    out += alphabet[((t ^ (t >>> 14)) >>> 0) % alphabet.length];
  }
  return out;
};
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ALNUM = B64.slice(0, 62);
const jwt = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
].join('.');

describe('envelope', () => {
  it('needs exactly { packages } with 1 to 1000 items', () => {
    expect(readCheckBody({})).toEqual({ ok: false, error: 'invalid_body' });
    expect(readCheckBody({ packages: [] })).toEqual({ ok: false, error: 'invalid_body' });
    expect(readCheckBody({ packages: 'x' })).toEqual({ ok: false, error: 'invalid_body' });
    expect(readCheckBody({ packages: [{ purl: 'pkg:npm/a@1.0.0' }], extra: 1 })).toEqual({
      ok: false,
      error: 'invalid_body',
    });
    expect(readCheckBody(null)).toEqual({ ok: false, error: 'invalid_body' });
    expect(readCheckBody({ packages: new Array(1001).fill(1) })).toEqual({
      ok: false,
      error: 'too_many_packages',
    });
    expect(readCheckBody({ packages: new Array(1000).fill(1) }).ok).toBe(true);
  });
});

describe('shape (bad_entry)', () => {
  it.each([
    ['not an object', 5],
    ['null', null],
    ['array', []],
    ['mixed forms', { purl: 'pkg:npm/a@1.0.0', name: 'a' }],
    ['extra key', { ...pkg('npm', 'a', '1.0.0'), x: 1 }],
    ['missing field', { ecosystem: 'npm', name: 'a' }],
    ['non-string', pkg('npm', 'a', 1 as never)],
    ['private not boolean', { ...pkg('npm', 'a', '1.0.0'), private: 'yes' }],
    ['over raw cap', pkg('npm', 'a'.repeat(513), '1.0.0')],
  ])('%s', (_n, e) => expect(reason(e)).toBe('bad_entry'));
});

describe('characters, URLs', () => {
  it.each([
    ['control', 'a\u0001b'],
    ['DEL', 'a\u007fb'],
    ['zero-width', 'a\u200bb'],
    ['bidi', 'a\u202eb'],
    ['tag', 'a\u{E0041}b'],
    ['variation selector', 'a\ufe0fb'],
    ['variation selector sup', 'a\u{E0100}b'],
    ['private use', 'a\ue000b'],
    ['unassigned', 'a\u0378b'],
  ])('%s → bad_characters', (_n, name) => expect(reason(pkg('npm', name, '1.0.0'))).toBe('bad_characters'));

  it('applies to every string', () => {
    expect(reason(pkg('np\u200bm', 'a', '1.0.0'))).toBe('bad_characters');
    expect(reason(pkg('npm', 'a', '1.0.\u200b0'))).toBe('bad_characters');
  });
  it('purl: decoded name and version are re-checked', () => {
    expect(reason({ purl: 'pkg:npm/a%E2%80%8Bb@1.0.0' })).toBe('bad_characters');
    expect(reason({ purl: 'pkg:npm/ab@1.0.0%E2%80%8B' })).toBe('bad_characters');
  });
  it('looks_like_url', () => {
    expect(reason(pkg('npm', 'https://evil.test/x', '1.0.0'))).toBe('looks_like_url');
    expect(reason(pkg('npm', 'a', 'git+https://host/x.git'))).toBe('looks_like_url');
    expect(reason({ purl: 'pkg:npm/a@1.0.0' + '/x://y' })).toBe('looks_like_url');
  });
});

describe('secrets', () => {
  const tokens = [
    ['ghp', '_', ALNUM.slice(0, 36)],
    ['gho', '_', ALNUM.slice(5, 41)],
    ['ghu', '_', ALNUM.slice(0, 30)],
    ['ghs', '_', ALNUM.slice(0, 31)],
    ['ghr', '_', ALNUM.slice(0, 32)],
    ['github', '_pat_', ALNUM.slice(0, 22), '_', 'abcdefgh'],
    ['npm', '_', ALNUM.slice(0, 36)],
    ['sk', '-', ALNUM.slice(0, 24)],
    ['xox', 'b', '-', '1234567890-abc'],
    ['AKIA', 'ABCDEFGHIJKLMNOP'],
    ['glpat', '-', 'abcdefghij0123456789'],
    ['pypi', '-', `${ALNUM}${ALNUM}`.slice(0, 60)],
  ].map((p) => p.join(''));
  it.each(tokens.map((t, i) => [i, t]))('token %s', (_i, t) => {
    expect(reason(pkg('npm', 'ok-name', t as string))).toBe('looks_like_secret');
    expect(reason(pkg('npm', t as string, '1.0.0'))).toBe('looks_like_secret');
  });
  it('credential in an authority, JWT, random base64, random hex, AWS-style key', () => {
    expect(reason(pkg('npm', 'deploy:s3cr3t@registry', '1.0.0'))).toBe('looks_like_secret');
    expect(reason(pkg('npm', 'a', jwt))).toBe('looks_like_secret');
    expect(reason(pkg('npm', jwt, '1.0.0'))).toBe('looks_like_secret');
    expect(reason(pkg('npm', 'a', rnd(B64, 40, 7)))).toBe('looks_like_secret');
    expect(reason(pkg('npm', 'a', rnd('0123456789abcdef', 64, 3)))).toBe('looks_like_secret');
    expect(reason(pkg('npm', 'a', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'))).toBe('looks_like_secret');
    expect(reason({ purl: 'pkg:npm/a@1.0.0?repository_url=https://u:p@host' })).toBe('looks_like_secret');
    expect(reason({ purl: `pkg:npm/a@1.0.0?token=${encodeURIComponent(rnd(B64, 40, 9))}` })).toBe(
      'looks_like_secret',
    );
  });
  it('several random samples are all caught', () => {
    for (let seed = 1; seed <= 50; seed++) {
      expect(reason(pkg('npm', 'a', rnd(B64, 40, seed)))).toBe('looks_like_secret');
      expect(reason(pkg('npm', 'a', rnd(ALNUM, 40, seed + 100)))).toBe('looks_like_secret');
    }
  });
});

describe('must accept', () => {
  const sha = 'a5ac7e51b41094c92402da3b24376905380afc29';
  it.each([
    [pkg('GitHub Actions', 'actions/checkout', sha), 'actions/checkout', sha],
    [
      pkg('Go', 'github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5', 'v5.7.0'),
      'github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5',
      '5.7.0',
    ],
    [
      pkg('Go', 'golang.org/x/net', 'v0.0.0-20231115185253-1b2c3d4e5f60'),
      'golang.org/x/net',
      '0.0.0-20231115185253-1b2c3d4e5f60',
    ],
    [
      pkg('Maven', 'org.springframework.boot:spring-boot-starter-web', '3.2.0'),
      'org.springframework.boot:spring-boot-starter-web',
      '3.2.0',
    ],
    [
      pkg('NuGet', 'Microsoft.Extensions.DependencyInjection.Abstractions', '8.0.0'),
      'microsoft.extensions.dependencyinjection.abstractions',
      '8.0.0',
    ],
    [pkg('PyPI', 'torch', '2.1.0+cu121'), 'torch', '2.1.0+cu121'],
    [pkg('PyPI', 'pypi-simple', '1.4.0'), 'pypi-simple', '1.4.0'],
    [
      pkg('npm', '@typescript-eslint/eslint-plugin', '6.13.2-alpha.0'),
      '@typescript-eslint/eslint-plugin',
      '6.13.2-alpha.0',
    ],
    [pkg('npm', 'sk-utils', '1.0.0'), 'sk-utils', '1.0.0'],
    [pkg('Debian:12', 'glibc', '2.36-9+deb12u4'), 'glibc', '2.36-9+deb12u4'],
    [pkg('Debian:12', 'glibc', '1:2.36-9'), 'glibc', '1:2.36-9'],
    [pkg('Red Hat', 'openssl', '1:3.0.7-24.el9'), 'openssl', '1:3.0.7-24.el9'],
    [pkg('RubyGems', 'nokogiri', '1.15.4-x86_64-linux'), 'nokogiri', '1.15.4-x86_64-linux'],
    [pkg('SwiftURL', 'github.com/apple/swift-nio', '2.62.0'), 'github.com/apple/swift-nio', '2.62.0'],
    [{ purl: 'pkg:npm/left-pad@1.3.0?repository_url=https://registry.npmjs.org' }, 'left-pad', '1.3.0'],
    [{ purl: `pkg:githubactions/actions/checkout@${sha}` }, 'actions/checkout', sha],
  ])('%j', (e, name, version) => {
    const r = one(e);
    expect(r.rejected).toEqual([]);
    expect(r.entries[0]?.ref).toMatchObject({ name, version });
  });
});

describe('NFKC, ecosystems, duplicates', () => {
  it('full-width names become ASCII', () => {
    expect(accepted(pkg('npm', 'ｌｏｄａｓｈ', '4.17.21'))?.name).toBe('lodash');
  });
  it('aliases and OS release keys', () => {
    expect(accepted(pkg('cargo', 'Serde_JSON', '1.0.0'))).toMatchObject({
      ecosystem: 'crates.io',
      name: 'serde-json',
    });
    expect(accepted(pkg('Ubuntu:22.04:LTS', 'curl', '7.81.0-1'))?.ecosystem).toBe('Ubuntu:22.04:LTS');
    expect(accepted(pkg('Alpine:v3.20', 'curl', '8.5.0-r0'))?.ecosystem).toBe('Alpine:v3.20');
    expect(accepted({ purl: 'pkg:deb/debian/openssl@3.0.11-1?distro=debian-12' })?.ecosystem).toBe(
      'Debian:12',
    );
  });
  it('bare Debian and Ubuntu need a release', () => {
    const r = readCheckBody({
      packages: [pkg('Debian', 'curl', '7.0'), { purl: 'pkg:deb/debian/curl@7.0' }],
    });
    expect(r).toMatchObject({
      ok: true,
      needsRelease: true,
      rejected: [
        { index: 0, reason: 'bad_ecosystem' },
        { index: 1, reason: 'bad_ecosystem' },
      ],
    });
  });
  it('folds duplicates after normalising and carries private over', () => {
    const r = readCheckBody({
      packages: [
        pkg('npm', 'Lodash', '1.0.0'),
        { ...pkg('npm', 'lodash', '1.0.0'), private: true },
        pkg('npm', 'lodash', '1.0.1'),
      ],
    });
    if (!r.ok) throw new Error();
    expect(r.rejected).toEqual([{ index: 1, reason: 'duplicate' }]);
    expect(r.entries.map((e) => [e.index, e.private])).toEqual([
      [0, true],
      [2, false],
    ]);
  });
  it('keeps only index and reason of a rejected entry', () => {
    const r = readCheckBody({ packages: [pkg('npm', 'Bad Name!', '1.0.0')] });
    if (!r.ok) throw new Error();
    expect(r.rejected).toEqual([{ index: 0, reason: 'bad_name' }]);
  });
});

describe('every reason', () => {
  it('bad_ecosystem, bad_name, bad_version, bad_purl', () => {
    expect(reason(pkg('nope', 'a', '1.0.0'))).toBe('bad_ecosystem');
    expect(reason(pkg('npm', 'A B', '1.0.0'))).toBe('bad_name');
    expect(reason(pkg('npm', 'a', '^1.2.0'))).toBe('bad_version');
    expect(reason({ purl: 'nope' })).toBe('bad_purl');
    expect(reason({ purl: 'pkg:npm/a' })).toBe('bad_purl');
  });
});

const GOOD_BAD: Record<string, { name: [string[], string[]]; version: [string[], string[]] }> = {
  npm: {
    name: [
      ['lodash', '@a/b', 'a.b_c~d'.replace('_', '-')],
      ['@a', '-a', 'A/b', 'a b'],
    ],
    version: [
      ['1.2.3', '1.0.0-rc.1+b'],
      ['1.2', '01.2.3', '^1.2.3', '1.x', '*', '>=1', '~1.2'],
    ],
  },
  PyPI: {
    name: [
      ['requests', 'a-b'],
      ['-a', 'a-'],
    ],
    version: [
      ['1.0', '2.1.0+cu121', '1!2.0.post1', '1.0rc1', 'v1.0.dev3'],
      ['1.x', 'abc', '^1.0'],
    ],
  },
  'crates.io': {
    name: [
      ['serde', 'a-b'],
      ['1a', 'a'.repeat(65)],
    ],
    version: [['1.0.0'], ['1.0']],
  },
  Go: {
    name: [
      ['golang.org/x/net', 'stdlib', 'toolchain'],
      ['nodots', 'a.b/ c'],
    ],
    version: [
      ['v1.2.3', '1.2.3', 'v1.2.3+incompatible'],
      ['vv1.2.3', '1.2'],
    ],
  },
  Maven: {
    name: [
      ['g:a', 'org.x:y-z'],
      ['ga', 'a:b:c'],
    ],
    version: [
      ['1.0', '3.2.0.RELEASE'],
      ['', '-1'],
    ],
  },
  RubyGems: {
    name: [['rails', 'a_b'], ['a b']],
    version: [
      ['7.0.1', '1.15.4-x86_64-linux'],
      ['v1', ''],
    ],
  },
  NuGet: {
    name: [['newtonsoft.json'], ['a b']],
    version: [
      ['1.0', '1.2.3.4', '1.0.0-beta+x'],
      ['1', '1.2.3.4.5'],
    ],
  },
  Packagist: {
    name: [
      ['symfony/console', 'a-b/c_d'],
      ['console', 'a--b--/c'],
    ],
    version: [['5.4.0'], ['']],
  },
  Hex: {
    name: [
      ['phoenix', 'a_b'],
      ['1a', 'a-b'],
    ],
    version: [['1.7.0'], ['1.7']],
  },
  Pub: {
    name: [
      ['http', '_a'],
      ['a-b', '1a'],
    ],
    version: [['1.0.0'], ['1.0']],
  },
  SwiftURL: {
    name: [['github.com/apple/swift-nio'], ['swift-nio', 'https://github.com/a/b']],
    version: [['2.62.0'], ['2']],
  },
  'GitHub Actions': {
    name: [['actions/checkout', 'a/b/c.yml'], ['checkout']],
    version: [['v4', 'a5ac7e51'], ['']],
  },
  'Debian:12': {
    name: [
      ['glibc', 'libc6-dev'],
      ['G', 'a b'],
    ],
    version: [
      ['2.36-9+deb12u4', '1:2.36-9'],
      ['a1', ''],
    ],
  },
  'Ubuntu:22.04:LTS': { name: [['curl'], ['C!']], version: [['7.81.0-1ubuntu1.15'], ['x']] },
  'Alpine:v3.20': { name: [['curl', 'Musl'], ['a b']], version: [['8.5.0-r0'], ['-r0']] },
  'Red Hat': { name: [['openssl'], ['a b']], version: [['1:3.0.7-24.el9'], ['']] },
};
describe('grammars', () => {
  for (const [eco, g] of Object.entries(GOOD_BAD)) {
    it(`${eco} names`, () => {
      for (const n of g.name[0]) expect(accepted(pkg(eco, n, g.version[0][0] as string)), n).toBeDefined();
      for (const n of g.name[1]) expect(reason(pkg(eco, n, g.version[0][0] as string)), n).toBeDefined();
    });
    it(`${eco} versions`, () => {
      for (const v of g.version[0]) expect(accepted(pkg(eco, g.name[0][0] as string, v)), v).toBeDefined();
      for (const v of g.version[1])
        expect(reason(pkg(eco, g.name[0][0] as string, v)), v).toBe('bad_version');
    });
  }
  it('rejects versions over 128 characters', () => {
    expect(validVersion('Maven', 'a'.repeat(129))).toBe(false);
    expect(reason(pkg('Maven', 'g:a', '1'.repeat(129)))).toBeDefined();
  });
  it('does not backtrack badly on a long near-miss', () => {
    const t = Date.now();
    reason(pkg('Packagist', `${'a'.repeat(200)}!/x`, '1.0'));
    reason(pkg('Packagist', `a/${'a-'.repeat(100)}!`, '1.0'));
    expect(Date.now() - t).toBeLessThan(200);
  });
});
