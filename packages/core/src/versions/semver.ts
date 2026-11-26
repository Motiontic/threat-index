/**
 * SemVer 2.0 precedence, parsed as leniently as the vectors need: an optional leading `v`, 1 to 3 numeric
 * core parts (missing parts are 0), and numeric parts after the third are treated as build metadata.
 * Shared by the npm, crates.io, Hex, SwiftURL, Go, GitHub Actions and Pub comparers.
 */

import {
  allDigits,
  compareCodeUnits,
  compareDigits,
  isAlnum,
  isDigit,
  isSafeVersion,
  makeComparer,
} from './common';
import type { Comparer } from './index';

export interface SemverParts {
  core: string[];
  pre: string[] | null;
  build: string[] | null;
}

/** Splits `s` at `.` into identifiers made of [0-9A-Za-z-]; null when one is empty or has another character. */
export function splitIdentifiers(s: string): string[] | null {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i <= s.length; i++) {
    if (i < s.length && s.charCodeAt(i) !== 46) {
      const c = s.charCodeAt(i);
      if (!isAlnum(c) && c !== 45) return null;
      continue;
    }
    if (i === start) return null;
    out.push(s.slice(start, i));
    start = i + 1;
  }
  return out;
}

export function parseSemver(v: string): SemverParts | null {
  if (!isSafeVersion(v)) return null;
  let i = v.charCodeAt(0) === 118 ? 1 : 0;
  const nums: string[] = [];
  for (;;) {
    const s = i;
    while (i < v.length && isDigit(v.charCodeAt(i))) i++;
    if (i === s) return null;
    nums.push(v.slice(s, i));
    if (v.charCodeAt(i) === 46) i++;
    else break;
  }
  const core = nums.slice(0, 3);
  while (core.length < 3) core.push('0');
  const extra = nums.slice(3);
  let pre: string[] | null = null;
  let build: string[] | null = null;
  if (v.charCodeAt(i) === 45) {
    const end = v.indexOf('+', i);
    const stop = end === -1 ? v.length : end;
    pre = splitIdentifiers(v.slice(i + 1, stop));
    if (pre === null) return null;
    i = stop;
  }
  if (v.charCodeAt(i) === 43) {
    build = splitIdentifiers(v.slice(i + 1));
    if (build === null) return null;
    i = v.length;
  }
  if (i < v.length) return null;
  if (extra.length > 0) build = [...extra, ...(build ?? [])];
  return { core, pre, build };
}

function compareIdentifier(a: string, b: string): -1 | 0 | 1 {
  const an = allDigits(a);
  const bn = allDigits(b);
  if (an && bn) return compareDigits(a, b);
  if (an !== bn) return an ? -1 : 1;
  return compareCodeUnits(a, b);
}

function compareIdentifierLists(a: string[], b: string[]): -1 | 0 | 1 {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const c = compareIdentifier(a[i] as string, b[i] as string);
    if (c !== 0) return c;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

export function compareSemverParts(a: SemverParts, b: SemverParts, orderBuild: boolean): -1 | 0 | 1 {
  const n = Math.max(a.core.length, b.core.length);
  for (let i = 0; i < n; i++) {
    const c = compareDigits(a.core[i] ?? '0', b.core[i] ?? '0');
    if (c !== 0) return c;
  }
  if (a.pre === null || b.pre === null) {
    if (a.pre !== b.pre) return a.pre === null ? 1 : -1;
  } else {
    const c = compareIdentifierLists(a.pre, b.pre);
    if (c !== 0) return c;
  }
  if (!orderBuild) return 0;
  if (a.build === null || b.build === null) return a.build === b.build ? 0 : a.build === null ? -1 : 1;
  return compareIdentifierLists(a.build, b.build);
}

export const semver: Comparer = makeComparer(parseSemver, (a, b) => compareSemverParts(a, b, false));
