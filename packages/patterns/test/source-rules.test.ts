import { describe, expect, it } from 'vitest';
import { fillTemplate, globToRegExp } from '../src/util';

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const sources = (import.meta as unknown as GlobImportMeta).glob('../src/*.ts', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const files = Object.keys(sources)
  .map((k) => k.replace('../src/', ''))
  .filter((f) => !f.endsWith('.test.ts'));
const code = (f: string) =>
  (sources[`../src/${f}`] ?? '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

describe('what packages/patterns/src may call', () => {
  it('never uses the global fetch, Date.now or new Date()', () => {
    // A call to `fetch(` that is not `x.fetch(`, a declaration (`function fetch(`, `fetch(ctx: ...)`) or a `.fetch` member.
    const globalFetch = /(?<![.\w])(?<!function )fetch\((?!ctx: PatternContext)/;
    for (const f of files) {
      const text = code(f);
      expect(text, f).not.toMatch(globalFetch);
      expect(text, f).not.toMatch(/globalThis\.fetch/);
      expect(text, f).not.toMatch(/Date\.now\(/);
      expect(text, f).not.toMatch(/new Date\(\)/);
    }
  });

  it('arms setTimeout only in http.ts, and never waits except through ctx.wait', () => {
    for (const f of files) {
      const text = code(f);
      if (f !== 'http.ts') expect(text, f).not.toMatch(/setTimeout/);
      expect(text, f).not.toMatch(/scheduler\./);
    }
    expect(code('http.ts').match(/setTimeout/g)).toHaveLength(1);
  });

  it('never throws NotImplementedError', () => {
    for (const f of files) expect(code(f), f).not.toContain('NotImplementedError');
  });

  it('calls ctx.fetch only in http.ts (types.ts keeps the old, unused conditionalGet)', () => {
    for (const f of files)
      if (f !== 'http.ts' && f !== 'types.ts') expect(code(f), f).not.toMatch(/ctx\.fetch\(/);
  });

  it('uses HTMLRewriter only inside a function', () => {
    const text = code('page.ts');
    expect(text).not.toMatch(/^(const|let|var)\s.*HTMLRewriter/m);
    expect(text).toContain('globalThis as { HTMLRewriter');
  });
});

describe('fillTemplate', () => {
  it('encodes each path segment and keeps the slashes', () => {
    expect(fillTemplate('https://x.test/{ref}.json', { ref: 'PyPI/PYSEC 2025?1' })).toBe(
      'https://x.test/PyPI/PYSEC%202025%3F1.json',
    );
  });
  it('rejects climbing segments and anything that leaves the origin', () => {
    expect(() => fillTemplate('https://x.test/{ref}.json', { ref: '../etc/passwd' })).toThrow(/climbs/);
    expect(() => fillTemplate('https://x.test/{ref}.json', { ref: 'a/./b' })).toThrow(/climbs/);
    expect(() => fillTemplate('https://x.test/{ref}', { ref: 'a\\b' })).toThrow(/climbs/);
    expect(() => fillTemplate('https://x.test/{ref}', {})).toThrow(/no value/);
    expect(() => fillTemplate('https://{ref}/x', { ref: 'evil.test' })).toThrow(/origin/);
  });
});

describe('globToRegExp', () => {
  it('* stays inside a segment and ** crosses segments', () => {
    const g = globToRegExp('cves/**/*.json');
    expect(g.test('cves/2025/3xxx/CVE-2025-3248.json')).toBe(true);
    expect(g.test('cves/CVE-1.json')).toBe(true);
    expect(g.test('cves/2025/x.py')).toBe(false);
    expect(g.test('other/2025/x.json')).toBe(false);
    expect(globToRegExp('a/*.json').test('a/b/c.json')).toBe(false);
  });
});
