/**
 * Alpine apk versions: numbers joined by `.`, then an optional single letter, then any number of
 * `_suffix[digits]`, then an optional `-r<digits>`.
 *
 * Order: suffixes `_alpha < _beta < _pre < _rc < (none) < _cvs < _svn < _git < _hg < _p`; a letter after the
 * numbers sorts above no letter; the `-r` revision compares last (missing = 0).
 *
 * The vectors also define how apk orders strings that are not clean versions, and `compare` follows them:
 * - a string that starts with a digit is read as far as it is well formed. An empty number between dots
 *   counts as 0, and a number after a letter is another number (`0.r1 < 0r2`). Whatever can't be read
 *   (`_blah`, `-ruff`, `-r-1`) is dropped, and a string with such a tail sorts below the same string without
 *   it (`1 > 1-ruff`) and equal to another with a tail (`1-ruff2 = 1-ruff1`);
 * - any other string (`.1`, `a`) orders by code unit, against every string.
 * `valid()` stays strict: only clean versions.
 */

import { compareCodeUnits, compareDigits, isDigit, isLower, isSafeVersion, sign } from './common';
import type { Comparer } from './index';

type Tok =
  | { t: 0; v: string } // number
  | { t: 1; v: string } // letter
  | { t: 2; rank: number; v: string }; // suffix

interface Apk {
  toks: Tok[];
  rev: string;
  tail: boolean; // something could not be read
  strict: boolean;
}

/** Suffix ranks around the end of the version (rank 0). */
const SUFFIX: Readonly<Record<string, number>> = {
  alpha: -4,
  beta: -3,
  pre: -2,
  rc: -1,
  cvs: 1,
  svn: 2,
  git: 3,
  hg: 4,
  p: 5,
};

function parseApk(v: string): Apk | null {
  if (!isDigit(v.charCodeAt(0))) return null;
  const toks: Tok[] = [];
  let strict = true;
  let tail = false;
  let i = 0;
  const digits = (): string => {
    const s = i;
    while (i < v.length && isDigit(v.charCodeAt(i))) i++;
    return v.slice(s, i);
  };
  for (;;) {
    const d = digits();
    if (d === '') {
      toks.push({ t: 0, v: '0' });
      strict = false;
    } else toks.push({ t: 0, v: d });
    if (v.charCodeAt(i) === 46) {
      i++;
      if (i >= v.length) {
        strict = false;
        break;
      }
    } else break;
  }
  if (isLower(v.charCodeAt(i))) {
    toks.push({ t: 1, v: v[i] as string });
    i++;
    for (;;) {
      const d = digits();
      if (d === '') break;
      toks.push({ t: 0, v: d });
      strict = false;
    }
  }
  while (v.charCodeAt(i) === 95) {
    const s = i + 1;
    let e = s;
    while (e < v.length && isLower(v.charCodeAt(e))) e++;
    const name = v.slice(s, e);
    const rank = Object.hasOwn(SUFFIX, name) ? (SUFFIX[name] as number) : null;
    if (rank === null) {
      tail = true;
      i = v.length;
      break;
    }
    i = e;
    toks.push({ t: 2, rank, v: digits() || '0' });
  }
  let rev = '0';
  if (i < v.length && v.charCodeAt(i) === 45 && v.charCodeAt(i + 1) === 114) {
    i += 2;
    rev = digits() || '0';
  }
  if (i < v.length) tail = true;
  return { toks, rev, tail, strict: strict && !tail };
}

function compareTok(a: Tok | undefined, b: Tok | undefined): number {
  if (a === undefined && b === undefined) return 0;
  if (a === undefined) return b?.t === 2 ? -b.rank : -1;
  if (b === undefined) return a.t === 2 ? a.rank : 1;
  if (a.t !== b.t) {
    // a suffix extends the component before it, so it sorts below a further number or letter
    if (a.t === 2) return -1;
    if (b.t === 2) return 1;
    return a.t < b.t ? -1 : 1;
  }
  if (a.t === 0) return compareDigits(a.v, b.v);
  if (a.t === 1) return compareCodeUnits(a.v, (b as { v: string }).v);
  const bs = b as { rank: number; v: string };
  if (a.rank !== bs.rank) return a.rank < bs.rank ? -1 : 1;
  return compareDigits(a.v, bs.v);
}

function compareApk(a: Apk, b: Apk): number {
  const n = Math.max(a.toks.length, b.toks.length);
  for (let i = 0; i < n; i++) {
    const c = compareTok(a.toks[i], b.toks[i]);
    if (c !== 0) return c;
  }
  const r = compareDigits(a.rev, b.rev);
  if (r !== 0) return r;
  return a.tail === b.tail ? 0 : a.tail ? -1 : 1;
}

function tryParse(v: unknown): Apk | null {
  if (!isSafeVersion(v)) return null;
  try {
    return parseApk(v);
  } catch {
    return null;
  }
}

export const alpine: Comparer = {
  valid: (v) => tryParse(v)?.strict === true,
  compare: (a, b) => {
    const pa = tryParse(a);
    const pb = tryParse(b);
    if (pa === null || pb === null) return compareCodeUnits(String(a), String(b));
    return sign(compareApk(pa, pb));
  },
};
