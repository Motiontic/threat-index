/**
 * Packagist (Composer). A leading `v` is stripped, then versions are ordered as PHP's `version_compare`
 * does: split at `.`, `-`, `_` and `+` and at each switch between digits and other characters; numbers
 * compare as numbers; words follow `other < dev < alpha = a < beta = b < RC = rc < # < pl = p` (a word ranks
 * by its prefix, case-sensitively); a number facing a word ranks like `#`; when one side runs out, a
 * remaining number makes that side higher and a remaining word is ranked against `#`.
 *
 * The vectors override the Composer step "pad the numeric part to four numbers and normalise the
 * stability suffix": they expect raw `version_compare` order (`v3.0 < v3.0.0-beta`, `1.0.0-ALPHA.1 =
 * 1.0.0-BETA.1`, `5.1.0-stable < 5.1.0-beta2`), so no padding or suffix rewriting happens here.
 * Branch versions (`dev-main`) can't be ordered, so they are invalid: a version starts with a digit.
 */

import { compareDigits, isAlnum, isDigit, isSafeVersion, makeComparer } from './common';
import type { Comparer } from './index';

type Tok = { n: string } | { w: number };

const W_HASH = 4;

/** version_compare's special forms, in its table order; a word matches the first entry it starts with. */
const FORMS: ReadonlyArray<readonly [string, number]> = [
  ['dev', 0],
  ['alpha', 1],
  ['a', 1],
  ['beta', 2],
  ['b', 2],
  ['RC', 3],
  ['rc', 3],
  ['#', W_HASH],
  ['pl', 5],
  ['p', 5],
];

function wordRank(word: string): number {
  for (const [name, rank] of FORMS) if (word.startsWith(name)) return rank;
  return -1;
}

function parsePackagist(v: string): Tok[] | null {
  let i = v.charCodeAt(0) === 118 || v.charCodeAt(0) === 86 ? 1 : 0;
  if (!isDigit(v.charCodeAt(i))) return null;
  const toks: Tok[] = [];
  while (i < v.length) {
    const c = v.charCodeAt(i);
    if (isDigit(c)) {
      const s = i;
      while (i < v.length && isDigit(v.charCodeAt(i))) i++;
      toks.push({ n: v.slice(s, i) });
    } else if (c === 46 || c === 45 || c === 95 || c === 43) {
      i++;
    } else if (c === 35) {
      toks.push({ w: W_HASH });
      i++;
    } else if (isAlnum(c)) {
      const s = i;
      while (i < v.length && isAlnum(v.charCodeAt(i)) && !isDigit(v.charCodeAt(i))) i++;
      toks.push({ w: wordRank(v.slice(s, i)) });
    } else return null;
  }
  return toks;
}

const rank = (t: Tok): number => ('w' in t ? t.w : W_HASH);

function comparePackagist(a: Tok[], b: Tok[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] as Tok;
    const y = b[i] as Tok;
    const c = 'n' in x && 'n' in y ? compareDigits(x.n, y.n) : rank(x) - rank(y);
    if (c !== 0) return c;
  }
  const tail = (rest: Tok[]): number => {
    for (let i = n; i < rest.length; i++) {
      const t = rest[i] as Tok;
      if ('n' in t) return 1;
      const c = t.w - W_HASH;
      if (c !== 0) return c;
    }
    return 0;
  };
  if (a.length > n) return tail(a);
  if (b.length > n) return -tail(b);
  return 0;
}

export const packagist: Comparer = makeComparer(
  (v) => (isSafeVersion(v) ? parsePackagist(v) : null),
  comparePackagist,
);
