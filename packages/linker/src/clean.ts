import { normaliseId } from '@ti/core/ids';

export const SUMMARY_MAX = 300;

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DATE = /^\d{4}-\d{2}-\d{2}/;

/** A normalised ID that is safe inside `docs/vuln/<key>.json`, or null. */
export function vulnId(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const id = normaliseId(raw);
  if (!SAFE_ID.test(id)) return null;
  return id;
}

/** Only http(s) URLs are kept. */
export function httpUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:' ? s : null;
  } catch {
    return null;
  }
}

/** A string that starts with an ISO date, or null. Keeps junk out of the hot-set date comparison. */
export function isoDate(raw: unknown): string | null {
  return typeof raw === 'string' && DATE.test(raw) ? raw : null;
}

export function text(raw: unknown): string | null {
  return typeof raw === 'string' && raw.trim() !== '' ? raw : null;
}

/** Sorted, unique JSON array of the non-empty strings. */
export function jsonList(values: Iterable<unknown>): string {
  const set = new Set<string>();
  for (const v of values) if (typeof v === 'string' && v !== '') set.add(v);
  return JSON.stringify([...set].sort());
}

/** A stored JSON array of strings; `[]` for anything else. */
export function readList(v: unknown): string[] {
  if (typeof v !== 'string') return [];
  try {
    const parsed: unknown = JSON.parse(v);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

/** CVSS in 0–10, else null. */
export function cvssScore(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 10 ? v : null;
}

/** A non-negative integer, else null. */
export function count(v: unknown): number | null {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 ? v : null;
}

export function cutSummary(s: string): string {
  if (s.length <= SUMMARY_MAX) return s;
  let out = s.slice(0, SUMMARY_MAX);
  const last = out.charCodeAt(out.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1); // never split a surrogate pair
  return out;
}

const norm = (v: unknown) => (v === undefined ? null : v);

/** True when any column other than `modified` differs. */
export function differs(row: Record<string, unknown>, stored: Record<string, unknown> | undefined): boolean {
  if (!stored) return true;
  return Object.keys(row).some((c) => c !== 'modified' && norm(row[c]) !== norm(stored[c]));
}
