/**
 * Maven `ComparableVersion`. Lower-cased; `.` and `-` separate items, a switch between digits and letters
 * acts like `-`, and each `-` opens a nested list. Qualifier order is
 * `alpha < beta < milestone < rc < snapshot < "" < sp`, unknown qualifiers sort after `sp`. Trailing null
 * items are dropped. A qualifier is lower than a list, a list is lower than a number.
 * `valid()` needs at least one digit and only letters, digits and `. - _ +`.
 */

import {
  compareCodeUnits,
  compareDigits,
  isAlnum,
  isDigit,
  isSafeVersion,
  lowerAscii,
  makeComparer,
} from './common';
import type { Comparer } from './index';

type Item = { k: 'n'; v: string } | { k: 's'; v: string } | { k: 'l'; items: Item[] };

const QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
const RELEASE_INDEX = '5';

/** Sort key for a qualifier: its index for known ones, otherwise "7-" + the text (after `sp`). */
function qualifierKey(value: string, followedByDigit: boolean): string {
  let q = value;
  if (followedByDigit && q.length === 1) {
    if (q === 'a') q = 'alpha';
    else if (q === 'b') q = 'beta';
    else if (q === 'm') q = 'milestone';
  }
  if (q === 'ga' || q === 'final' || q === 'release') q = '';
  else if (q === 'cr') q = 'rc';
  const idx = QUALIFIERS.indexOf(q);
  return idx === -1 ? `${QUALIFIERS.length}-${q}` : String(idx);
}

const isNull = (it: Item): boolean =>
  it.k === 'n'
    ? compareDigits(it.v, '0') === 0
    : it.k === 's'
      ? it.v === RELEASE_INDEX
      : it.items.length === 0;

function normalize(list: Item[]): void {
  for (let i = list.length - 1; i >= 0; i--) {
    const last = list[i] as Item;
    if (isNull(last)) list.splice(i, 1);
    else if (last.k !== 'l') break;
  }
}

/** Letters, digits and `. - _ +`; `needDigit` is what `valid()` adds. */
function mavenChars(raw: string, needDigit: boolean): boolean {
  let hasDigit = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (isDigit(c)) hasDigit = true;
    else if (!isAlnum(c) && c !== 46 && c !== 45 && c !== 95 && c !== 43) return false;
  }
  return hasDigit || !needDigit;
}

function parseMaven(raw: string): Item | null {
  if (!mavenChars(raw, false)) return null;
  const v = lowerAscii(raw);
  const root: Item = { k: 'l', items: [] };
  const stack: Item[] = [root];
  let list = root;
  const add = (it: Item): void => {
    (list as { items: Item[] }).items.push(it);
  };
  const parseItem = (digit: boolean, s: string, followed = false): Item =>
    digit ? { k: 'n', v: s } : { k: 's', v: qualifierKey(s, followed) };
  const open = (): void => {
    const nl: Item = { k: 'l', items: [] };
    add(nl);
    list = nl;
    stack.push(nl);
  };
  let isDig = false;
  let start = 0;
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c === 46) {
      add(i === start ? { k: 'n', v: '0' } : parseItem(isDig, v.slice(start, i)));
      start = i + 1;
    } else if (c === 45) {
      add(i === start ? { k: 'n', v: '0' } : parseItem(isDig, v.slice(start, i)));
      start = i + 1;
      open();
    } else if (isDigit(c)) {
      if (!isDig && i > start) {
        add(parseItem(false, v.slice(start, i), true));
        start = i;
        open();
      }
      isDig = true;
    } else {
      if (isDig && i > start) {
        add(parseItem(true, v.slice(start, i)));
        start = i;
        open();
      }
      isDig = false;
    }
  }
  if (v.length > start) add(parseItem(isDig, v.slice(start)));
  while (stack.length > 0) {
    const current = stack.pop() as { items: Item[] };
    const items = current.items;
    normalize(items);
    // The vectors need `1-1 = 1-ga-1`: once `ga` is dropped, a nested list holding only one list is that
    // list. The top-level list is left alone (`0.0.0-2021-05-17 < 20.0.0`).
    while (current !== root && items.length === 1 && (items[0] as Item).k === 'l')
      items.splice(0, 1, ...(items[0] as { items: Item[] }).items);
  }
  return root;
}

function cmpItem(a: Item, b: Item | null): number {
  if (a.k === 'n') {
    if (b === null) return isNull(a) ? 0 : 1;
    if (b.k === 'n') return compareDigits(a.v, b.v);
    return 1;
  }
  if (a.k === 's') {
    if (b === null) return compareCodeUnits(a.v, RELEASE_INDEX);
    if (b.k === 's') return compareCodeUnits(a.v, b.v);
    return -1;
  }
  if (b === null) return a.items.length === 0 ? 0 : cmpItem(a.items[0] as Item, null);
  if (b.k === 'n') return -1;
  if (b.k === 's') return 1;
  const n = Math.max(a.items.length, b.items.length);
  for (let i = 0; i < n; i++) {
    const l = a.items[i] ?? null;
    const r = b.items[i] ?? null;
    const c = l === null ? (r === null ? 0 : -cmpItem(r, l)) : cmpItem(l, r);
    if (c !== 0) return c;
  }
  return 0;
}

const ordered = makeComparer(
  (v) => (isSafeVersion(v) ? parseMaven(v) : null),
  (a, b) => cmpItem(a, b),
);

/**
 * `valid()` also needs a digit (`RELEASE` is not a version), but `compare` orders digit-less strings such as
 * `stable` the same way Maven does, because the vectors do (`profiles_01 < stable < 0.11.0`).
 */
export const maven: Comparer = {
  valid: (v) => isSafeVersion(v) && mavenChars(v, true) && ordered.valid(v),
  compare: ordered.compare,
};
