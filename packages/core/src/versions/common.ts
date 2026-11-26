/**
 * Shared rules for every comparer: the input guard, big-number digit comparison, and the order for
 * strings a comparer cannot parse. Hand-written scanners only: no regular expressions anywhere in this
 * folder (a test enforces it).
 */
import type { Comparer } from './index';

export const MAX_VERSION_LENGTH = 128;

/** 1–128 characters, each printable ASCII (0x21–0x7E). Checks typeof and length first, so a huge input costs O(1). */
export function isSafeVersion(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const n = v.length;
  if (n === 0 || n > MAX_VERSION_LENGTH) return false;
  for (let i = 0; i < n; i++) {
    const c = v.charCodeAt(i);
    if (c < 0x21 || c > 0x7e) return false;
  }
  return true;
}

export const isDigit = (c: number): boolean => c >= 48 && c <= 57;
export const isLower = (c: number): boolean => c >= 97 && c <= 122;
export const isUpper = (c: number): boolean => c >= 65 && c <= 90;
export const isAlpha = (c: number): boolean => isLower(c) || isUpper(c);
export const isAlnum = (c: number): boolean => isDigit(c) || isAlpha(c);

/** ASCII lower-case by hand (no locale involved). */
export function lowerAscii(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += isUpper(c) ? String.fromCharCode(c + 32) : s[i];
  }
  return out;
}

/** True when every character of `s` is an ASCII digit and `s` is not empty. */
export function allDigits(s: string): boolean {
  if (s.length === 0) return false;
  for (let i = 0; i < s.length; i++) if (!isDigit(s.charCodeAt(i))) return false;
  return true;
}

/** Code-unit order as exactly -1, 0 or 1. */
export function compareCodeUnits(a: string, b: string): -1 | 0 | 1 {
  return a === b ? 0 : a < b ? -1 : 1;
}

/**
 * Two runs of ASCII digits compared as whole numbers of any size: skip leading zeros, then the longer run
 * is larger, then code-unit order.
 */
export function compareDigits(a: string, b: string): -1 | 0 | 1 {
  let i = 0;
  let j = 0;
  while (i < a.length && a.charCodeAt(i) === 48) i++;
  while (j < b.length && b.charCodeAt(j) === 48) j++;
  const la = a.length - i;
  const lb = b.length - j;
  if (la !== lb) return la < lb ? -1 : 1;
  for (; i < a.length; i++, j++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(j);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Order for strings a comparer can't parse: invalid sorts below every valid version; two invalid strings compare by code unit. */
export function compareInvalid(a: string, aValid: boolean, b: string, bValid: boolean): -1 | 0 | 1 {
  if (aValid !== bValid) return aValid ? 1 : -1;
  return compareCodeUnits(a, b);
}

export const sign = (n: number): -1 | 0 | 1 => (n < 0 ? -1 : n > 0 ? 1 : 0);

/**
 * Builds a Comparer from a parser and an order over parsed values. `valid` never throws; `compare` never
 * throws and falls back to `compareInvalid` when either side does not parse.
 */
export function makeComparer<T>(parse: (v: string) => T | null, order: (a: T, b: T) => number): Comparer {
  const safeParse = (v: unknown): T | null => {
    if (!isSafeVersion(v)) return null;
    try {
      return parse(v);
    } catch {
      return null;
    }
  };
  return {
    valid: (v) => safeParse(v) !== null,
    compare: (a, b) => {
      const pa = safeParse(a);
      const pb = safeParse(b);
      if (pa !== null && pb !== null) return sign(order(pa, pb));
      return compareInvalid(String(a), pa !== null, String(b), pb !== null);
    },
  };
}
