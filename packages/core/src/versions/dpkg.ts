/**
 * Debian Policy 5.6.12: `[epoch:]upstream[-revision]`. The epoch is the digits before the first `:`; the
 * revision is everything after the last `-`. The upstream part starts with a digit and uses
 * `[A-Za-z0-9.+~-:]` (`-` only with a revision, `:` only with an epoch); the revision uses `[A-Za-z0-9.+~]`.
 * Each part alternates runs of non-digits and digits. In a non-digit run `~` sorts below the end of the run,
 * the end below letters, letters below everything else. Digit runs compare as numbers.
 */

import { compareDigits, isAlnum, isAlpha, isDigit, makeComparer } from './common';
import type { Comparer } from './index';

interface Dpkg {
  epoch: string;
  upstream: string;
  revision: string;
}

function parseDpkg(v: string): Dpkg | null {
  let epoch = '0';
  let rest = v;
  const colon = v.indexOf(':');
  if (colon !== -1) {
    epoch = v.slice(0, colon);
    if (epoch.length === 0) return null;
    for (let i = 0; i < epoch.length; i++) if (!isDigit(epoch.charCodeAt(i))) return null;
    rest = v.slice(colon + 1);
  }
  const dash = rest.lastIndexOf('-');
  const upstream = dash === -1 ? rest : rest.slice(0, dash);
  const revision = dash === -1 ? '' : rest.slice(dash + 1);
  if (upstream.length === 0 || !isDigit(upstream.charCodeAt(0))) return null;
  if (dash !== -1 && revision.length === 0) return null;
  for (let i = 0; i < upstream.length; i++) {
    const c = upstream.charCodeAt(i);
    if (isAlnum(c) || c === 46 || c === 43 || c === 126) continue;
    if (c === 45 && dash !== -1) continue;
    if (c === 58 && colon !== -1) continue;
    return null;
  }
  for (let i = 0; i < revision.length; i++) {
    const c = revision.charCodeAt(i);
    if (!(isAlnum(c) || c === 46 || c === 43 || c === 126)) return null;
  }
  return { epoch, upstream, revision };
}

function order(c: number): number {
  if (c === -1) return 0;
  if (c === 126) return -1;
  if (isAlpha(c)) return c;
  return c + 256;
}

function compareNonDigit(a: string, i: number, b: string, j: number): { c: number; i: number; j: number } {
  for (;;) {
    const ca = i < a.length && !isDigit(a.charCodeAt(i)) ? a.charCodeAt(i) : -1;
    const cb = j < b.length && !isDigit(b.charCodeAt(j)) ? b.charCodeAt(j) : -1;
    if (ca === -1 && cb === -1) return { c: 0, i, j };
    const oa = order(ca);
    const ob = order(cb);
    if (oa !== ob) return { c: oa < ob ? -1 : 1, i, j };
    if (ca !== -1) i++;
    if (cb !== -1) j++;
  }
}

function verrevcmp(a: string, b: string): -1 | 0 | 1 {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    const r = compareNonDigit(a, i, b, j);
    if (r.c !== 0) return r.c < 0 ? -1 : 1;
    i = r.i;
    j = r.j;
    const si = i;
    const sj = j;
    while (i < a.length && isDigit(a.charCodeAt(i))) i++;
    while (j < b.length && isDigit(b.charCodeAt(j))) j++;
    const c = compareDigits(a.slice(si, i), b.slice(sj, j));
    if (c !== 0) return c;
  }
  return 0;
}

export const dpkg: Comparer = makeComparer(parseDpkg, (a, b) => {
  const e = compareDigits(a.epoch, b.epoch);
  if (e !== 0) return e;
  const u = verrevcmp(a.upstream, b.upstream);
  if (u !== 0) return u;
  return verrevcmp(a.revision, b.revision);
});
