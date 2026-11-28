/** Shared by the change-list pattern, the `big-file` job and ti-api: cursor pairs and the ref filter. */

/** A change-list cursor value: `[time, ref]`. */
export type Pair = [time: string, ref: string];

/** The longest cursor value (JSON text) ti-api accepts from a job. */
export const MAX_PAIR_CHARS = 512;

/** A `[time, ref]` JSON pair of strings, or null. */
export function readPair(value: string | null | undefined): Pair | null {
  if (!value) return null;
  try {
    const v = JSON.parse(value) as unknown;
    if (Array.isArray(v) && typeof v[0] === 'string' && typeof v[1] === 'string') return [v[0], v[1]];
  } catch {
    // not JSON
  }
  return null;
}

/** Like `readPair`, but also at most `MAX_PAIR_CHARS` long with a time that parses as a date. */
export function readCheckedPair(value: string | null | undefined): Pair | null {
  if (!value || value.length > MAX_PAIR_CHARS) return null;
  const pair = readPair(value);
  return pair && !Number.isNaN(Date.parse(pair[0])) ? pair : null;
}

/** Orders by time in ms, then by ref. Times must parse (callers check). */
export function compareLines(a: { ms: number; ref: string }, b: { ms: number; ref: string }): number {
  return a.ms - b.ms || (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0);
}

/** `compareLines` for pairs. */
export function comparePairs(a: Pair, b: Pair): number {
  return compareLines({ ms: Date.parse(a[0]), ref: a[1] }, { ms: Date.parse(b[0]), ref: b[1] });
}

/** Whether a ref's text before the first `/` is in `prefixes` (no list: every ref is kept). */
export function refKept(ref: string, prefixes: readonly string[] | undefined): boolean {
  if (!prefixes) return true;
  const i = ref.indexOf('/');
  return i > 0 && prefixes.includes(ref.slice(0, i));
}

/** A job's partial cursor is valid when it is strictly after `from` and not after `to`. */
export function cursorInBounds(reached: Pair, from: Pair, to: Pair): boolean {
  return comparePairs(reached, from) > 0 && comparePairs(reached, to) <= 0;
}
