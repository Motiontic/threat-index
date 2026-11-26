import { describe, expect, it } from 'vitest';
import { ECOSYSTEMS } from '../packages';
import {
  exemptionReason,
  expectedSign,
  mustComparer,
  parseVectors,
  skipsCompare,
  VECTOR_FILES,
} from './test-support';

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const files = (import.meta as unknown as GlobImportMeta).glob('../../../../fixtures/versions/*/*.txt', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const byPath = new Map(
  Object.entries(files).map(([k, v]) => [k.slice(k.indexOf('fixtures/versions/') + 18), v] as const),
);

describe('vector files', () => {
  it('every .txt file is mapped, every mapped file exists, every ecosystem is covered', () => {
    expect([...byPath.keys()].filter((p) => !(p in VECTOR_FILES))).toEqual([]);
    expect(Object.keys(VECTOR_FILES).filter((p) => !byPath.has(p))).toEqual([]);
    const covered = new Set(Object.values(VECTOR_FILES).flat());
    expect(ECOSYSTEMS.filter((e) => !covered.has(e))).toEqual([]);
  });

  it('parseVectors throws on a malformed line', () => {
    expect(() => parseVectors('1 < 2\n1 <  2')).toThrow(/malformed/);
    expect(() => parseVectors('1 ? 2')).toThrow(/malformed/);
    expect(parseVectors('# c\n// c\n\n1 < 2')).toEqual([{ line: 4, a: '1', op: '<', b: '2' }]);
  });

  const totals = { lines: 0, checks: 0, exempt: 0 };
  for (const [path, ecosystems] of Object.entries(VECTOR_FILES)) {
    for (const ecosystem of ecosystems) {
      it(`${path} passes both ways for ${ecosystem}`, () => {
        const text = byPath.get(path);
        if (text === undefined) throw new Error(`missing ${path}`);
        const vectors = parseVectors(text);
        const c = mustComparer(ecosystem);
        const failures: string[] = [];
        let exempt = 0;
        for (const v of vectors) {
          const want = expectedSign(v.op);
          const ex = exemptionReason(ecosystem, v.a) ?? exemptionReason(ecosystem, v.b);
          if (ex) exempt++;
          if (skipsCompare(ecosystem, v.a) || skipsCompare(ecosystem, v.b)) continue;
          if (!ex && (!c.valid(v.a) || !c.valid(v.b)))
            failures.push(`line ${v.line}: ${v.a} / ${v.b} not valid`);
          const got = c.compare(v.a, v.b);
          const back = c.compare(v.b, v.a);
          if (got !== want || back + want !== 0)
            failures.push(`line ${v.line}: ${v.a} ${v.op} ${v.b} gave ${got}/${back}`);
        }
        totals.lines += vectors.length;
        totals.checks += vectors.length * 2;
        totals.exempt += exempt;
        console.log(`vectors ${path} [${ecosystem}]: ${vectors.length} lines, ${exempt} exempt`);
        expect(failures.slice(0, 20)).toEqual([]);
      });
    }
  }
});
