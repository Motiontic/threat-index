import { SOURCES } from '@ti/sources/registry';
import { displayFor, type ReadEnv } from './preview';

/** Bindings the world routes use: the public read bindings plus `ti_world`. */
export type WorldEnv = ReadEnv & { DB_WORLD: D1Database };

export const WORLD_TTL = 300;
export const PAGE_SIZE = 25;
export const MAX_PAGE = 40;
const MAX_Q = 100;
// biome-ignore lint/suspicious/noControlCharactersInRegex: this is the check for control characters
const CONTROL = /[\u0000-\u001f\u007f]/;

export interface ListQuery<X> {
  q?: string;
  page: number;
  extra: X;
}
export type ListQueryError = { error: 'bad_query' | 'bad_page' | string };

/**
 * `q` (trimmed, 1–100 chars, no control characters, lower-cased) and `page` (1–40, default 1). `extra` reads the
 * route's own parameters and returns either its value or `{ error }`. Unknown parameters are ignored.
 */
export function parseListQuery<X>(
  url: URL,
  extra: (sp: URLSearchParams) => X | ListQueryError,
): ListQuery<X> | ListQueryError {
  const sp = url.searchParams;
  let q: string | undefined;
  const rawQ = sp.get('q');
  if (rawQ !== null) {
    const t = rawQ.trim();
    if (t.length > 0 || rawQ.length > 0) {
      if (t.length < 1 || t.length > MAX_Q || CONTROL.test(t)) return { error: 'bad_query' };
      q = t.toLowerCase();
    }
  }
  const rawPage = sp.get('page');
  let page = 1;
  if (rawPage !== null) {
    if (!/^\d{1,3}$/.test(rawPage)) return { error: 'bad_page' };
    page = Number(rawPage);
    if (page < 1 || page > MAX_PAGE) return { error: 'bad_page' };
  }
  const x = extra(sp);
  if (typeof x === 'object' && x !== null && 'error' in x) return x as ListQueryError;
  const out: ListQuery<X> = { page, extra: x as X };
  if (q !== undefined) out.q = q;
  return out;
}

export const isListError = (v: unknown): v is ListQueryError =>
  typeof v === 'object' && v !== null && 'error' in v;

/** `%…%` with `\`, `%` and `_` escaped; use with `ESCAPE '\'`. */
export function likePattern(q: string): string {
  return `%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
}

export interface Visible {
  full: string[];
  link: string[];
}

/** Registry sources whose display is `full` or `link`. Hidden and unknown sources are in neither list. */
export async function visibleSources(env: Pick<ReadEnv, 'SETTINGS'>): Promise<Visible> {
  const display = await displayFor(
    env.SETTINGS,
    SOURCES.map((s) => s.id),
  );
  const out: Visible = { full: [], link: [] };
  for (const [id, mode] of display) {
    if (mode === 'full') out.full.push(id);
    else if (mode === 'link') out.link.push(id);
  }
  out.full.sort();
  out.link.sort();
  return out;
}

export const allVisible = (v: Visible): string[] => [...v.full, ...v.link].sort();

/** `?${from}, ?${from+1}, …` for `n` numbered parameters, so one list can be bound once and used twice. */
export function placeholders(from: number, n: number): string {
  return Array.from({ length: n }, (_, i) => `?${from + i}`).join(',');
}

/** The cache path, built from validated values in a fixed order: `/v1/breaches?page=2&q=acme`. */
export function cacheKey(path: string, parts: [string, string | number | undefined][]): string {
  const qs = parts
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .sort()
    .join('&');
  return qs ? `${path}?${qs}` : path;
}

/** 1–200 printable ASCII characters. */
export const validPrintableId = (s: string): boolean => /^[\x20-\x7e]{1,200}$/.test(s);

/** Only http: and https: URLs pass. */
export function safeUrl(u: string | null | undefined): string | undefined {
  if (!u) return undefined;
  try {
    const p = new URL(u).protocol;
    return p === 'http:' || p === 'https:' ? u : undefined;
  } catch {
    return undefined;
  }
}

export const optional = <T>(v: T | null | undefined): T | undefined =>
  v === null || v === undefined ? undefined : v;
