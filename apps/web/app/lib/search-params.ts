// Validation of the visitor's search query string. Unknown values are dropped; nothing else is forwarded.
import type { EntryType, SearchParams, SearchSort, Severity } from '../data/types';

export const MAX_QUERY = 200;
export const SEARCH_TYPES: EntryType[] = ['vuln', 'breach', 'ai', 'mal', 'tech', 'term'];
/** Every type has an API behind it: `/v1/search` for vuln and mal, the world list routes for the rest. */
/** The types `/v1/search` answers. */
export const SEARCH_API_TYPES: EntryType[] = ['vuln', 'mal'];
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function parseSearchParams(qs: URLSearchParams): SearchParams {
  const out: SearchParams = {};
  const q = (qs.get('q') ?? '').trim();
  if (q && q.length <= MAX_QUERY) out.q = q;
  else if (q) out.q = q.slice(0, MAX_QUERY).trim();
  const type = SEARCH_TYPES.filter((t) => qs.getAll('type').includes(t));
  if (type.length > 0) out.type = type;
  if (qs.getAll('sig').includes('kev')) out.sig = ['kev'];
  const sev = qs.get('sev');
  const found = SEVERITIES.find((s) => s === sev);
  if (found) out.sev = found;
  const year = qs.get('year');
  if (year && /^(19|20)\d{2}$/.test(year)) out.year = year;
  const sort = qs.get('sort');
  if (sort === 'rel' || sort === 'new') out.sort = sort satisfies SearchSort;
  const cursor = qs.get('cursor');
  if (cursor && /^[A-Za-z0-9_-]{1,200}$/.test(cursor)) out.cursor = cursor;
  return out;
}

export function hasCriteria(p: SearchParams): boolean {
  return Boolean(p.q || p.type || p.sig || p.sev || p.year);
}

/** The same params as a query string, with an optional replacement cursor. */
export function paramsToQuery(p: SearchParams, cursor?: string | null): string {
  const qs = new URLSearchParams();
  if (p.q) qs.set('q', p.q);
  for (const t of p.type ?? []) qs.append('type', t);
  for (const s of p.sig ?? []) qs.append('sig', s);
  if (p.sev) qs.set('sev', p.sev);
  if (p.year) qs.set('year', p.year);
  if (p.sort) qs.set('sort', p.sort);
  const c = cursor === undefined ? p.cursor : cursor;
  if (c) qs.set('cursor', c);
  const text = qs.toString();
  return text ? `?${text}` : '';
}

/** The `/search?…` link that re-runs a saved search, rebuilt from its stored query and params. */
export function savedSearchHref(s: {
  query: string;
  params: { type?: string[]; sig?: string[]; sev?: string[]; year?: string[]; sort?: string };
}): string {
  const qs = new URLSearchParams();
  if (s.query) qs.set('q', s.query);
  for (const t of s.params.type ?? []) qs.append('type', t);
  for (const g of s.params.sig ?? []) qs.append('sig', g);
  for (const v of s.params.sev ?? []) qs.append('sev', v);
  for (const y of s.params.year ?? []) qs.append('year', y);
  if (s.params.sort) qs.set('sort', s.params.sort);
  // Re-validate on the way out: only values the search page accepts reach the link.
  const clean = paramsToQuery(parseSearchParams(qs));
  return `/search${clean}`;
}
