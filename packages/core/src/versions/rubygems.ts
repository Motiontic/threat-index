/**
 * RubyGems `Gem::Version`: a version starts with a digit, then `.`-separated alphanumeric segments, then an
 * optional `-` prerelease (a `-` means `.pre.`). Segments also split at each switch between letters and
 * digits. Trailing zero segments are dropped, the shorter list is padded with 0, a letter segment is lower
 * than a number.
 */

import { compareCodeUnits, compareDigits, isAlnum, isDigit, makeComparer } from './common';
import type { Comparer } from './index';

type Seg = { n: string } | { s: string };

function parseGem(v: string): Seg[] | null {
  if (!isDigit(v.charCodeAt(0))) return null;
  const raw: string[] = [];
  let i = 0;
  let inPre = false;
  let start = 0;
  const flush = (end: number): boolean => {
    if (end === start) return false;
    raw.push(v.slice(start, end));
    return true;
  };
  for (; i <= v.length; i++) {
    const c = i < v.length ? v.charCodeAt(i) : -1;
    if (c === 46 || c === -1) {
      if (!flush(i)) return null;
      start = i + 1;
    } else if (c === 45) {
      if (!inPre) {
        if (!flush(i)) return null;
        raw.push('pre');
        inPre = true;
        start = i + 1;
      } else {
        if (i > start) raw.push(v.slice(start, i));
        raw.push('pre');
        start = i + 1;
      }
    } else if (!isAlnum(c)) return null;
  }
  const segs: Seg[] = [];
  for (const part of raw) {
    let j = 0;
    while (j < part.length) {
      const s = j;
      const dig = isDigit(part.charCodeAt(j));
      while (j < part.length && isDigit(part.charCodeAt(j)) === dig) j++;
      const text = part.slice(s, j);
      segs.push(dig ? { n: text } : { s: text });
    }
  }
  return segs;
}

const isZeroSeg = (s: Seg): boolean => 'n' in s && compareDigits(s.n, '0') === 0;

function canonical(segs: Seg[]): Seg[] {
  const firstStr = segs.findIndex((s) => 's' in s);
  const nums = firstStr === -1 ? segs.slice() : segs.slice(0, firstStr);
  const strs = firstStr === -1 ? [] : segs.slice(firstStr);
  while (nums.length > 0 && isZeroSeg(nums[nums.length - 1] as Seg)) nums.pop();
  while (strs.length > 0 && isZeroSeg(strs[strs.length - 1] as Seg)) strs.pop();
  return [...nums, ...strs];
}

function compareGem(a: Seg[], b: Seg[]): -1 | 0 | 1 {
  const x = canonical(a);
  const y = canonical(b);
  const n = Math.max(x.length, y.length);
  const zero: Seg = { n: '0' };
  for (let i = 0; i < n; i++) {
    const l = x[i] ?? zero;
    const r = y[i] ?? zero;
    if ('n' in l && 'n' in r) {
      const c = compareDigits(l.n, r.n);
      if (c !== 0) return c;
    } else if ('s' in l && 's' in r) {
      const c = compareCodeUnits(l.s, r.s);
      if (c !== 0) return c;
    } else return 's' in l ? -1 : 1;
  }
  return 0;
}

export const rubygems: Comparer = makeComparer(parseGem, compareGem);
