/**
 * NuGet: 1 to 4 numeric parts (missing parts are 0), no leading `v`. The prerelease uses SemVer 2.0
 * identifier rules but compares case-insensitively. Build metadata is ignored.
 */

import { isDigit, isSafeVersion, lowerAscii, makeComparer } from './common';
import type { Comparer } from './index';
import { compareSemverParts, type SemverParts, splitIdentifiers } from './semver';

function parseNuget(v: string): SemverParts | null {
  if (!isSafeVersion(v)) return null;
  let i = 0;
  const core: string[] = [];
  for (;;) {
    const s = i;
    while (i < v.length && isDigit(v.charCodeAt(i))) i++;
    if (i === s) return null;
    core.push(v.slice(s, i));
    if (v.charCodeAt(i) === 46) i++;
    else break;
  }
  if (core.length > 4) return null;
  while (core.length < 4) core.push('0');
  let pre: string[] | null = null;
  if (v.charCodeAt(i) === 45) {
    const end = v.indexOf('+', i);
    const stop = end === -1 ? v.length : end;
    pre = splitIdentifiers(lowerAscii(v.slice(i + 1, stop)));
    if (pre === null) return null;
    i = stop;
  }
  if (v.charCodeAt(i) === 43) {
    if (splitIdentifiers(v.slice(i + 1)) === null) return null;
    i = v.length;
  }
  return i < v.length ? null : { core, pre, build: null };
}

export const nuget: Comparer = makeComparer(parseNuget, (a, b) => compareSemverParts(a, b, false));
