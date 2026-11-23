import { searchTerms } from '@ti/core/search';

/** Parsing and validation of `GET /v1/search` parameters, and the paging cursor. */

export const SEARCH_TYPES = ['vuln', 'breach', 'ai', 'mal', 'tech', 'term'] as const;
export type SearchType = (typeof SEARCH_TYPES)[number];
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const MAX_QUERY_CHARS = 200;
export const MAX_TERMS = 8;
export const MAX_OFFSET = 1000;
export const DEFAULT_LIMIT = 20;
export const MAX_LIMIT = 50;

export interface SearchParams {
  q: string; // trimmed
  terms: string[]; // first MAX_TERMS of searchTerms(q)
  types: SearchType[];
  kev: boolean;
  sevs: Severity[];
  years: string[];
  sort: 'rel' | 'new';
  limit: number;
  offset: number;
  fingerprint: string;
}

export type ParseResult = { ok: true; params: SearchParams } | { ok: false };

/** Short FNV-1a hash (8 hex digits). Not a security boundary: it only ties a cursor to its query. */
function fnv(text: string): string {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(text)) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

export function encodeCursor(offset: number, fingerprint: string): string {
  const json = JSON.stringify({ v: 1, o: offset, f: fingerprint });
  return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeCursor(raw: string): { o: number; f: string } | null {
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(raw)) return null;
  try {
    const padded = raw.replace(/-/g, '+').replace(/_/g, '/');
    const data: unknown = JSON.parse(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4)));
    if (!data || typeof data !== 'object') return null;
    const { v, o, f } = data as Record<string, unknown>;
    if (v !== 1 || typeof f !== 'string' || typeof o !== 'number' || !Number.isInteger(o)) return null;
    if (o < 0 || o > MAX_OFFSET) return null;
    return { o, f };
  } catch {
    return null;
  }
}

function single(sp: URLSearchParams, name: string): string | null | undefined {
  const all = sp.getAll(name);
  if (all.length > 1) return undefined; // repeated where only one value makes sense
  return all[0] ?? null;
}

function oneOf<T extends string>(values: string[], allowed: readonly T[]): T[] | null {
  const out: T[] = [];
  for (const v of values) {
    if (!(allowed as readonly string[]).includes(v)) return null;
    if (!out.includes(v as T)) out.push(v as T);
  }
  return out;
}

export function parseSearchParams(sp: URLSearchParams): ParseResult {
  const bad: ParseResult = { ok: false };
  const rawQ = single(sp, 'q');
  if (rawQ === undefined) return bad;
  const q = (rawQ ?? '').trim();
  if (q.length > MAX_QUERY_CHARS) return bad;

  const types = oneOf(sp.getAll('type'), SEARCH_TYPES);
  const sigs = oneOf(sp.getAll('sig'), ['kev'] as const);
  const sevs = oneOf(sp.getAll('sev'), SEVERITIES);
  if (!types || !sigs || !sevs) return bad;

  const years: string[] = [];
  for (const y of sp.getAll('year')) {
    if (!/^\d{4}$/.test(y) || Number(y) < 1999 || Number(y) > 2100) return bad;
    if (!years.includes(y)) years.push(y);
  }

  const sortRaw = single(sp, 'sort');
  if (sortRaw === undefined || (sortRaw !== null && sortRaw !== 'rel' && sortRaw !== 'new')) return bad;
  const sort = sortRaw ?? (q ? 'rel' : 'new');

  const limitRaw = single(sp, 'limit');
  if (limitRaw === undefined) return bad;
  let limit = DEFAULT_LIMIT;
  if (limitRaw !== null) {
    if (!/^\d{1,3}$/.test(limitRaw)) return bad;
    limit = Number(limitRaw);
    if (limit < 1 || limit > MAX_LIMIT) return bad;
  }

  const terms = searchTerms(q).slice(0, MAX_TERMS);
  const fingerprint = fnv(
    JSON.stringify([q, [...types].sort(), sigs.length > 0, [...sevs].sort(), [...years].sort(), sort]),
  );

  const cursorRaw = single(sp, 'cursor');
  if (cursorRaw === undefined) return bad;
  let offset = 0;
  if (cursorRaw !== null) {
    const cursor = decodeCursor(cursorRaw);
    if (!cursor || cursor.f !== fingerprint) return bad;
    offset = cursor.o;
  }

  return {
    ok: true,
    params: { q, terms, types, kev: sigs.length > 0, sevs, years, sort, limit, offset, fingerprint },
  };
}

/** The same request, parameters sorted, as a cache key. Nothing from headers goes in. */
export function canonicalUrl(url: URL): string {
  const entries = [...url.searchParams].sort(([a, av], [b, bv]) =>
    a === b ? (av < bv ? -1 : av > bv ? 1 : 0) : a < b ? -1 : 1,
  );
  const sorted = new URLSearchParams(entries);
  return `${url.origin}${url.pathname}?${sorted}`;
}
