/**
 * GitHub Actions: SemVer rules with or without the `v` (workflow tags look like `v4`, GHSA data like
 * `46.0.1`). A floating tag such as `v4` is compared as its `.0` version (`4.0.0`); resolving it to the
 * release it points at is out of scope. A 40-character hexadecimal commit SHA is never valid, even when it
 * is all digits.
 */

import { isAlnum, makeComparer } from './common';
import type { Comparer } from './index';
import { compareSemverParts, parseSemver } from './semver';

function isHexSha(v: string): boolean {
  if (v.length !== 40) return false;
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    const hex = (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
    if (!hex || !isAlnum(c)) return false;
  }
  return true;
}

export const githubActions: Comparer = makeComparer(
  (v) => (isHexSha(v) ? null : parseSemver(v)),
  (a, b) => compareSemverParts(a, b, false),
);
