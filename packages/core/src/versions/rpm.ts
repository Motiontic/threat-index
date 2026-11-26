/**
 * RPM: `[epoch:]version[-release]`, epoch 0 by default. Epoch compares as a number, then the version, then
 * the release, each with rpmvercmp: separators (anything that is not a letter, a digit, `~` or `^`) are
 * skipped; `~` sorts below everything, even the end; `^` sorts above the end but below anything else; a digit
 * run beats a letter run; digit runs compare as numbers, letter runs by code unit. A missing release sorts
 * below any release, even an empty one. The comparison is total, so any safe string is valid.
 */

import {
  compareCodeUnits,
  compareDigits,
  isAlnum,
  isAlpha,
  isDigit,
  isSafeVersion,
  makeComparer,
} from './common';
import type { Comparer } from './index';

interface Rpm {
  epoch: string;
  version: string;
  release: string | null;
}

function parseRpm(v: string): Rpm | null {
  if (!isSafeVersion(v)) return null;
  let epoch = '0';
  let rest = v;
  const colon = v.indexOf(':');
  if (colon > 0) {
    let digits = true;
    for (let i = 0; i < colon; i++) if (!isDigit(v.charCodeAt(i))) digits = false;
    if (digits) {
      epoch = v.slice(0, colon);
      rest = v.slice(colon + 1);
    }
  }
  const dash = rest.lastIndexOf('-');
  if (dash === -1) return { epoch, version: rest, release: null };
  return { epoch, version: rest.slice(0, dash), release: rest.slice(dash + 1) };
}

const isSep = (c: number): boolean => !isAlnum(c) && c !== 126 && c !== 94;

function rpmvercmp(a: string, b: string): -1 | 0 | 1 {
  if (a === b) return 0;
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    while (i < a.length && isSep(a.charCodeAt(i))) i++;
    while (j < b.length && isSep(b.charCodeAt(j))) j++;
    const ca = i < a.length ? a.charCodeAt(i) : -1;
    const cb = j < b.length ? b.charCodeAt(j) : -1;
    if (ca === 126 || cb === 126) {
      if (ca !== 126) return 1;
      if (cb !== 126) return -1;
      i++;
      j++;
      continue;
    }
    if (ca === 94 || cb === 94) {
      if (ca === -1) return -1;
      if (cb === -1) return 1;
      if (ca !== 94) return 1;
      if (cb !== 94) return -1;
      i++;
      j++;
      continue;
    }
    if (ca === -1 || cb === -1) break;
    const num = isDigit(ca);
    const si = i;
    const sj = j;
    if (num) {
      while (i < a.length && isDigit(a.charCodeAt(i))) i++;
      while (j < b.length && isDigit(b.charCodeAt(j))) j++;
    } else {
      while (i < a.length && isAlpha(a.charCodeAt(i))) i++;
      while (j < b.length && isAlpha(b.charCodeAt(j))) j++;
    }
    if (sj === j) return num ? 1 : -1;
    const c = num
      ? compareDigits(a.slice(si, i), b.slice(sj, j))
      : compareCodeUnits(a.slice(si, i), b.slice(sj, j));
    if (c !== 0) return c;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
}

export const rpm: Comparer = makeComparer(parseRpm, (a, b) => {
  const e = compareDigits(a.epoch, b.epoch);
  if (e !== 0) return e;
  const v = rpmvercmp(a.version, b.version);
  if (v !== 0) return v;
  if (a.release === null || b.release === null)
    return a.release === b.release ? 0 : a.release === null ? -1 : 1;
  return rpmvercmp(a.release, b.release);
});
