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

/** An ISO 8601 date-time with `Z` or a numeric offset: the only form read the same in every time zone. */
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/**
 * For values from outside ti-api: at most `MAX_PAIR_CHARS` long, exactly two strings, a non-empty ref, and an ISO
 * time with `Z` or an offset that parses as a date.
 */
export function readCheckedPair(value: string | null | undefined): Pair | null {
  if (!value || value.length > MAX_PAIR_CHARS) return null;
  let v: unknown;
  try {
    v = JSON.parse(value);
  } catch {
    return null;
  }
  if (!Array.isArray(v) || v.length !== 2) return null;
  const [time, ref] = v as unknown[];
  if (typeof time !== 'string' || typeof ref !== 'string' || ref === '') return null;
  if (!ISO_TIME.test(time) || Number.isNaN(Date.parse(time))) return null;
  return [time, ref];
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
