import { describe, expect, it } from 'vitest';
import { ECOSYSTEMS, type Ecosystem } from '../packages';
import { mustComparer, parseVectors, VECTOR_FILES } from './test-support';

/** mulberry32: a seeded PRNG, so a failure reproduces from its seed. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEED = 0x7e57;
const TOKENS = [
  'a',
  'b',
  'rc',
  'alpha',
  'beta',
  'dev',
  'post',
  'pre',
  'sp',
  'snapshot',
  'final',
  'ga',
  'pl',
  'p',
  'r',
  'git',
  'cvs',
  'svn',
  'hg',
  'incompatible',
];
const ALPHABET = ['0', '1', '2', '9', '.', '-', '+', '~', '^', ':', '!', '_', 'v'];

function randomPrintable(rand: () => number): string {
  const n = Math.floor(rand() * 201);
  let s = '';
  for (let i = 0; i < n; i++) s += String.fromCharCode(0x20 + Math.floor(rand() * 0x5f));
  return s;
}

function randomVersionLike(rand: () => number): string {
  const n = 1 + Math.floor(rand() * 24);
  let s = '';
  for (let i = 0; i < n; i++) {
    s +=
      rand() < 0.3
        ? (TOKENS[Math.floor(rand() * TOKENS.length)] as string)
        : (ALPHABET[Math.floor(rand() * ALPHABET.length)] as string);
  }
  return s;
}

const FIXED = [
  '9'.repeat(128),
  '1.'.repeat(64),
  '-'.repeat(128),
  '~'.repeat(128),
  '1-'.repeat(64),
  'a1'.repeat(64),
  '0'.repeat(128),
  '\u0000\u0001\u001f\u007f\u0080',
  '\ud800',
  '1.0.\udc00',
  '1.0.0\u{1f600}',
  '😀'.repeat(70),
  '1'.repeat(129),
  '1'.repeat(10_000),
  '1'.repeat(1_000_000),
];

function inputsFor(rand: () => number): string[] {
  const out: string[] = [...FIXED];
  for (let i = 0; i < 2000; i++) out.push(randomPrintable(rand));
  for (let i = 0; i < 2000; i++) out.push(randomVersionLike(rand));
  return out;
}

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const files = (import.meta as unknown as GlobImportMeta).glob('../../../../fixtures/versions/*/*.txt', {
  query: '?raw',
  import: 'default',
  eager: true,
});

function pool(e: Ecosystem): string[] {
  const set = new Set<string>();
  for (const [key, text] of Object.entries(files)) {
    const path = key.slice(key.indexOf('fixtures/versions/') + 18);
    if (!VECTOR_FILES[path]?.includes(e)) continue;
    for (const v of parseVectors(text)) {
      set.add(v.a);
      set.add(v.b);
    }
  }
  const c = mustComparer(e);
  return [...set].filter((v) => c.valid(v)).sort();
}

describe('fuzz', () => {
  for (const e of ECOSYSTEMS) {
    it(`${e}: never throws, and compare is a total order on what it is given`, () => {
      const c = mustComparer(e);
      const rand = mulberry32(SEED);
      const inputs = inputsFor(rand);
      let slowest = 0;
      let slowestInput = '';
      let current = '';
      const timed = <T>(f: () => T): T => {
        const t = performance.now();
        const r = f();
        let d = performance.now() - t;
        // A GC or scheduler pause hits one call once; slow code is slow every time. Keep the best of three.
        for (let retry = 0; retry < 2 && d >= 10; retry++) {
          const t2 = performance.now();
          f();
          d = Math.min(d, performance.now() - t2);
        }
        if (d > slowest) {
          slowest = d;
          slowestInput = current;
        }
        return r;
      };
      const start = performance.now();
      for (let i = 0; i < inputs.length; i++) {
        const s = inputs[i] as string;
        current = `#${i} ${JSON.stringify(s.slice(0, 80))} (${s.length})`;
        const other = inputs[(i * 7 + 1) % inputs.length] as string;
        const v = timed(() => c.valid(s));
        expect(typeof v, `seed ${SEED}, valid(${JSON.stringify(s.slice(0, 40))})`).toBe('boolean');
        const self = timed(() => c.compare(s, s));
        const ab = timed(() => c.compare(s, other));
        const ba = timed(() => c.compare(other, s));
        if (![-1, 0, 1].includes(ab) || ![-1, 0, 1].includes(ba) || self !== 0 || ab + ba !== 0) {
          throw new Error(
            `seed ${SEED}: ${JSON.stringify(s.slice(0, 60))} vs ${JSON.stringify(other.slice(0, 60))}: self ${self}, ${ab}/${ba}`,
          );
        }
      }
      const total = performance.now() - start;
      expect(slowest, `slowest call ${slowest} ms on ${slowestInput}`).toBeLessThan(10);
      expect(total, `fuzz run ${total} ms`).toBeLessThan(500);
    });

    it(`${e}: sorting valid vector versions gives a consistent order (transitivity)`, () => {
      const c = mustComparer(e);
      const rand = mulberry32(SEED + 1);
      const all = pool(e);
      expect(all.length).toBeGreaterThan(0);
      const picked = all.slice();
      for (let i = picked.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [picked[i], picked[j]] = [picked[j] as string, picked[i] as string];
      }
      const sample = picked.slice(0, 150);
      const sorted = sample.slice().sort((x, y) => c.compare(x, y));
      const bad: string[] = [];
      for (let i = 0; i < sorted.length; i++) {
        for (let j = i + 1; j < sorted.length; j++) {
          if (c.compare(sorted[i] as string, sorted[j] as string) > 0)
            bad.push(`${sorted[i]} > ${sorted[j]}`);
        }
      }
      expect(bad.slice(0, 5)).toEqual([]);
    });
  }
});
