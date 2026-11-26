/**
 * PEP 440 (https://peps.python.org/pep-0440/). `valid()` accepts only normalisable PEP 440 versions. Strings
 * that the old `packaging.version.LegacyVersion` accepted (`0.1-bulbasaur`) are invalid, but `compare` still
 * orders them: below every PEP 440 version, and among themselves by LegacyVersion's key. Strings the guard
 * rejects sort below those, by code unit.
 */

import {
  allDigits,
  compareCodeUnits,
  compareDigits,
  isDigit,
  isSafeVersion,
  lowerAscii,
  sign,
} from './common';
import type { Comparer } from './index';

interface Pep {
  epoch: string;
  release: string[];
  /** -1: dev release with no pre or post (sorts below every pre-release); 0 a, 1 b, 2 rc; 3: none. */
  preKind: number;
  preNum: string;
  post: string | null;
  dev: string | null;
  local: string[] | null;
}

const isSep = (c: number): boolean => c === 46 || c === 45 || c === 95;
const isAlnumLower = (c: number): boolean => isDigit(c) || (c >= 97 && c <= 122);

function startsWithAt(s: string, i: number, word: string): boolean {
  return s.startsWith(word, i);
}

function parsePep(raw: string): Pep | null {
  const v = lowerAscii(raw);
  let i = v.charCodeAt(0) === 118 ? 1 : 0;
  const digits = (): string => {
    const s = i;
    while (i < v.length && isDigit(v.charCodeAt(i))) i++;
    return v.slice(s, i);
  };
  let epoch = '0';
  let d = digits();
  if (d === '') return null;
  if (v.charCodeAt(i) === 33) {
    epoch = d;
    i++;
    d = digits();
    if (d === '') return null;
  }
  const release = [d];
  while (v.charCodeAt(i) === 46 && isDigit(v.charCodeAt(i + 1))) {
    i++;
    release.push(digits());
  }
  const skipSep = (): void => {
    if (isSep(v.charCodeAt(i))) i++;
  };
  // pre-release
  let preKind = 3;
  let preNum = '0';
  let hasPre = false;
  {
    const save = i;
    skipSep();
    let kind = -1;
    for (const [word, k] of [
      ['alpha', 0],
      ['beta', 1],
      ['preview', 2],
      ['pre', 2],
      ['rc', 2],
      ['a', 0],
      ['b', 1],
      ['c', 2],
    ] as const) {
      if (startsWithAt(v, i, word)) {
        kind = k;
        i += word.length;
        break;
      }
    }
    if (kind === -1) i = save;
    else {
      skipSep();
      preKind = kind;
      preNum = digits() || '0';
      hasPre = true;
    }
  }
  // post-release
  let post: string | null = null;
  if (v.charCodeAt(i) === 45 && isDigit(v.charCodeAt(i + 1))) {
    i++;
    post = digits();
  } else {
    const save = i;
    skipSep();
    let matched = false;
    for (const word of ['post', 'rev', 'r']) {
      if (startsWithAt(v, i, word)) {
        i += word.length;
        matched = true;
        break;
      }
    }
    if (matched) {
      skipSep();
      post = digits() || '0';
    } else i = save;
  }
  // dev release
  let dev: string | null = null;
  {
    const save = i;
    skipSep();
    if (startsWithAt(v, i, 'dev')) {
      i += 3;
      skipSep();
      dev = digits() || '0';
    } else i = save;
  }
  let local: string[] | null = null;
  if (v.charCodeAt(i) === 43) {
    i++;
    local = [];
    for (;;) {
      const s = i;
      while (i < v.length && isAlnumLower(v.charCodeAt(i))) i++;
      if (i === s) return null;
      local.push(v.slice(s, i));
      if (isSep(v.charCodeAt(i))) i++;
      else break;
    }
  }
  if (i < v.length) return null;
  if (!hasPre && post === null && dev !== null) preKind = -1;
  return { epoch, release, preKind, preNum, post, dev, local };
}

function compareRelease(a: string[], b: string[]): -1 | 0 | 1 {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const c = compareDigits(a[i] ?? '0', b[i] ?? '0');
    if (c !== 0) return c;
  }
  return 0;
}

function compareLocal(a: string[] | null, b: string[] | null): -1 | 0 | 1 {
  if (a === null || b === null) return a === b ? 0 : a === null ? -1 : 1;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] as string;
    const y = b[i] as string;
    const xn = allDigits(x);
    const yn = allDigits(y);
    if (xn !== yn) return xn ? 1 : -1;
    const c = xn ? compareDigits(x, y) : compareCodeUnits(x, y);
    if (c !== 0) return c;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

function comparePep(a: Pep, b: Pep): -1 | 0 | 1 {
  let c: -1 | 0 | 1 = compareDigits(a.epoch, b.epoch);
  if (c !== 0) return c;
  c = compareRelease(a.release, b.release);
  if (c !== 0) return c;
  if (a.preKind !== b.preKind) return a.preKind < b.preKind ? -1 : 1;
  if (a.preKind >= 0 && a.preKind < 3) {
    c = compareDigits(a.preNum, b.preNum);
    if (c !== 0) return c;
  }
  if (a.post === null || b.post === null) {
    if (a.post !== b.post) return a.post === null ? -1 : 1;
  } else {
    c = compareDigits(a.post, b.post);
    if (c !== 0) return c;
  }
  if (a.dev === null || b.dev === null) {
    if (a.dev !== b.dev) return a.dev === null ? 1 : -1;
  } else {
    c = compareDigits(a.dev, b.dev);
    if (c !== 0) return c;
  }
  return compareLocal(a.local, b.local);
}

/**
 * LegacyVersion's sort key: lower-case, split into digit runs, letter runs, `.`, `-` and runs of anything
 * else; `pre`/`preview`/`rc` become `c`, `-` becomes `final-`, `dev` becomes `@`; parts that are not
 * numbers are marked and a `*final` closes the list. Numeric parts hold the digits, others `*text`.
 */
function legacyKey(raw: string): string[] {
  const s = lowerAscii(raw);
  const parts: string[] = [];
  const push = (tok: string): void => {
    let part = tok;
    if (part === 'pre' || part === 'preview' || part === 'rc') part = 'c';
    else if (part === '-') part = 'final-';
    else if (part === 'dev') part = '@';
    if (part === '' || part === '.') return;
    const text = isDigit(part.charCodeAt(0)) ? part : `*${part}`;
    if (text.charCodeAt(0) === 42) {
      if (text < '*final') while (parts.length > 0 && parts[parts.length - 1] === '*final-') parts.pop();
      while (
        parts.length > 0 &&
        parts[parts.length - 1] !== undefined &&
        isZero(parts[parts.length - 1] as string)
      )
        parts.pop();
    }
    parts.push(text);
  };
  let i = 0;
  while (i < s.length) {
    const c = s.charCodeAt(i);
    const start = i;
    if (isDigit(c)) {
      while (i < s.length && isDigit(s.charCodeAt(i))) i++;
    } else if (c >= 97 && c <= 122) {
      while (i < s.length && s.charCodeAt(i) >= 97 && s.charCodeAt(i) <= 122) i++;
    } else if (c === 46 || c === 45) {
      i++;
    } else {
      while (i < s.length) {
        const d = s.charCodeAt(i);
        if (isDigit(d) || (d >= 97 && d <= 122) || d === 46 || d === 45) break;
        i++;
      }
    }
    push(s.slice(start, i));
  }
  push('*final'.slice(1));
  return parts;
}

function isZero(p: string): boolean {
  return allDigits(p) && compareDigits(p, '0') === 0;
}

function compareLegacy(a: string, b: string): -1 | 0 | 1 {
  const ka = legacyKey(a);
  const kb = legacyKey(b);
  const n = Math.min(ka.length, kb.length);
  for (let i = 0; i < n; i++) {
    const x = ka[i] as string;
    const y = kb[i] as string;
    const xn = x.charCodeAt(0) !== 42;
    const yn = y.charCodeAt(0) !== 42;
    if (xn !== yn) return xn ? 1 : -1;
    const c = xn ? compareDigits(x, y) : compareCodeUnits(x, y);
    if (c !== 0) return c;
  }
  return ka.length === kb.length ? 0 : ka.length < kb.length ? -1 : 1;
}

function tryParse(v: unknown): Pep | null {
  if (!isSafeVersion(v)) return null;
  try {
    return parsePep(v);
  } catch {
    return null;
  }
}

/** 2 for a PEP 440 version, 1 for a legacy string (safe input), 0 for anything the guard rejects. */
function tier(v: unknown, parsed: Pep | null): number {
  return parsed !== null ? 2 : isSafeVersion(v) ? 1 : 0;
}

export const pypi: Comparer = {
  valid: (v) => tryParse(v) !== null,
  compare: (a, b) => {
    try {
      const pa = tryParse(a);
      const pb = tryParse(b);
      if (pa !== null && pb !== null) return comparePep(pa, pb);
      const ta = tier(a, pa);
      const tb = tier(b, pb);
      if (ta !== tb) return ta < tb ? -1 : 1;
      return ta === 1 ? compareLegacy(String(a), String(b)) : compareCodeUnits(String(a), String(b));
    } catch {
      return sign(compareCodeUnits(String(a), String(b)));
    }
  },
};
