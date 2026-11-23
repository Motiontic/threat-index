/** Helpers shared by the US breach-notice parsers. No `parse` here: this is not a parser module. */

const MAX_NAME = 200;
const MAX_COUNT = 1e10;

/** True for a real calendar date (leap days included). */
function realDate(y: number, m: number, d: number): boolean {
  if (m < 1 || m > 12 || d < 1) return false;
  const dim = [
    31,
    y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return d <= (dim[m - 1] as number);
}

const pad = (n: number, w: number) => String(n).padStart(w, '0');

/** `MM/DD/YYYY` (1–2 digit month and day) to `YYYY-MM-DD`; real calendar dates only. */
export function usDate(s: unknown): string | undefined {
  if (typeof s !== 'string') return undefined;
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(s.trim());
  if (!m) return undefined;
  const [mo, d, y] = [Number(m[1]), Number(m[2]), Number(m[3])];
  return realDate(y, mo, d) ? `${pad(y, 4)}-${pad(mo, 2)}-${pad(d, 2)}` : undefined;
}

/** The leading `YYYY-MM-DD` of a string, if it is a real date. */
export function isoDay(s: unknown): string | undefined {
  if (typeof s !== 'string') return undefined;
  const m = /^(\d{4})-(\d{2})-(\d{2})(?![\d])/.exec(s.trim());
  if (!m) return undefined;
  return realDate(Number(m[1]), Number(m[2]), Number(m[3])) ? `${m[1]}-${m[2]}-${m[3]}` : undefined;
}

/** Trim, collapse whitespace, strip control characters, cap at 200 characters. Empty gives `undefined`. */
export function cleanName(s: unknown): string | undefined {
  if (typeof s !== 'string') return undefined;
  const t = s
    .replace(/\p{Cc}/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_NAME)
    .trim();
  return t === '' ? undefined : t;
}

/** A non-negative safe integer, or digits with optional thousands commas. Anything else is `undefined`. */
export function toCount(s: unknown): number | undefined {
  let n: number;
  if (typeof s === 'number') n = s;
  else if (typeof s === 'string' && /^(?:\d{1,3}(?:,\d{3})+|\d+)$/.test(s.trim()))
    n = Number(s.trim().replace(/,/g, ''));
  else return undefined;
  return Number.isSafeInteger(n) && n >= 0 && n <= MAX_COUNT ? n : undefined;
}

/** A stable notice id: parts lower-cased, runs of non-`[a-z0-9]` become `-`, joined with `:`, ≤ 200 chars. */
export function noticeKey(...parts: string[]): string {
  return parts
    .map((p) => p.toLowerCase().replace(/[^a-z0-9]+/g, '-'))
    .join(':')
    .slice(0, 200);
}

/** The input a parser accepts: one item body or an array of them. Anything else throws. */
export function bodies(input: unknown, who: string): Record<string, unknown>[] {
  const list = Array.isArray(input) ? input : [input];
  for (const b of list) {
    if (typeof b !== 'object' || b === null || Array.isArray(b))
      throw new Error(`${who}: expected an object or an array of objects`);
  }
  return list as Record<string, unknown>[];
}

/** Keys of `body` not in `known`, added to `unknown`. */
export function noteUnknown(
  body: Record<string, unknown>,
  known: ReadonlySet<string>,
  unknown: Set<string>,
): void {
  for (const k of Object.keys(body)) if (!known.has(k)) unknown.add(k);
}
