import { MAX_STRUCTURED_CHARS } from '../tools/shared';

/** The most items read for one page. No page of 32,000 characters can hold this many. */
export const MAX_PAGE_ITEMS = 400;
/** Room for the sealed cursor in the size check. */
const CURSOR_RESERVE = 480;

/**
 * Fits the items read from one offset to the output budget. `remaining` is how many items are left from that
 * offset in all (not only the ones read). Keeps at least one item so a page always moves forward.
 */
export function fitPage(
  items: unknown[],
  remaining: number,
  build: (n: number, more: boolean) => Record<string, unknown>,
): { data: Record<string, unknown>; kept: number; more: boolean } {
  const size = (n: number, more: boolean) =>
    JSON.stringify({ ...build(n, more), nextCursor: 'x'.repeat(CURSOR_RESERVE) }).length;
  let kept = items.length;
  if (items.length < remaining || size(kept, false) > MAX_STRUCTURED_CHARS) {
    let lo = 0;
    let hi = items.length;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (size(mid, true) <= MAX_STRUCTURED_CHARS) lo = mid;
      else hi = mid - 1;
    }
    kept = Math.max(lo, 1);
  }
  const more = kept < remaining;
  return { data: build(kept, more), kept, more };
}
