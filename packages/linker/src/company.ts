import { differs, isoDate, readList, text } from './clean';
import type { Row } from './tables';

/** 'cik:0000123456' | 'domain:example.com' | 'name:<slug>:<juris>'. Always matches ^[a-z0-9:.@-]{1,200}$. */
export type CompanyKey = string;

const DOMAIN = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const MAX_ALIASES = 50;
const DAY_MS = 86_400_000;

/**
 * The `companyKey` convention: `NoticeRecord` has no CIK or domain field, so a parser that knows an
 * identifier passes it in `companyKey` as a hint:
 *
 * - `cik:<1-10 digits>`: SEC filers (the 8-K parser sets this). Normalised to `cik:` + 10 digits.
 * - `domain:<host>`: sources keyed by site (HIBP). Lower-cased, a leading `www.` dropped; must match
 *   `^[a-z0-9-]+(\.[a-z0-9-]+)+$` and be at most 253 characters.
 *
 * Any other value, or an invalid one, is ignored (null) and the notice is matched by name.
 */
export function hintKey(raw: unknown): { key: CompanyKey; cik?: string; domain?: string } | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase();
  const cik = /^cik:(\d{1,10})$/.exec(s);
  if (cik) {
    const digits = (cik[1] as string).padStart(10, '0');
    return { key: `cik:${digits}`, cik: digits };
  }
  if (s.startsWith('domain:')) {
    let host = s.slice('domain:'.length);
    if (host.startsWith('www.')) host = host.slice(4);
    if (host.length <= 253 && DOMAIN.test(host)) return { key: `domain:${host}`, domain: host };
  }
  return null;
}

/** Legal suffixes dropped from the end of a name, as token sequences (longest first). */
const SUFFIXES: string[][] = [
  'l l c',
  'n a',
  'inc',
  'incorporated',
  'llc',
  'llp',
  'lp',
  'ltd',
  'limited',
  'corp',
  'corporation',
  'co',
  'company',
  'plc',
  'pllc',
  'pc',
  'pa',
  'na',
  'sa',
  'ag',
  'gmbh',
].map((s) => s.split(' '));
SUFFIXES.sort((a, b) => b.length - a.length);

/** The name as a lower-case [a-z0-9 ] string without legal suffixes; '' when nothing is left. */
export function normaliseName(raw: string): string {
  let s = String(raw ?? '')
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase();
  const dba = / (?:dba|d\/b\/a) /.exec(` ${s} `);
  if (dba) s = ` ${s} `.slice(0, dba.index);
  const words = s
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, ' ')
    .split(' ')
    .filter(Boolean);
  if (words[0] === 'the') words.shift();
  const before = words.join(' ');
  let stripped = true;
  while (stripped && words.length > 0) {
    stripped = false;
    for (const suffix of SUFFIXES) {
      if (
        words.length >= suffix.length &&
        suffix.every((w, i) => words[words.length - suffix.length + i] === w)
      ) {
        words.length -= suffix.length;
        stripped = true;
        break;
      }
    }
  }
  return words.length > 0 ? words.join(' ') : before;
}

/** 'us-ca' (ISO 3166-2), 'us' / 'gb' (ISO 3166-1 alpha-2), else 'xx'. */
export function jurisdictionCode(raw: unknown): string {
  if (typeof raw !== 'string') return 'xx';
  const s = raw.trim();
  if (/^[A-Za-z]{2}$/.test(s) || /^[A-Za-z]{2}-[A-Za-z0-9]{1,3}$/.test(s)) return s.toLowerCase();
  return 'xx';
}

export function nameKey(norm: string, juris: string): CompanyKey {
  return `name:${norm.replace(/ /g, '-').slice(0, 100)}:${juris}`;
}

export interface Span {
  from: string;
  to: string;
}

/** The first 10 characters of a string that is a real calendar date, else null. */
function calendarDate(raw: unknown): string | null {
  const s = isoDate(raw)?.slice(0, 10);
  if (!s) return null;
  const t = Date.parse(`${s}T00:00:00Z`);
  return Number.isNaN(t) || new Date(t).toISOString().slice(0, 10) !== s ? null : s;
}

/** When the incident happened (not when letters went out): AG letters follow an 8-K by months. */
export function incidentSpan(n: {
  occurredFrom?: unknown;
  occurredTo?: unknown;
  discovered?: unknown;
  notified?: unknown;
}): Span | null {
  const first = (...xs: unknown[]): string | null => {
    for (const x of xs) {
      const d = calendarDate(x);
      if (d) return d;
    }
    return null;
  };
  const from = first(n.occurredFrom, n.occurredTo, n.discovered, n.notified);
  const to = first(n.occurredTo, n.occurredFrom, n.discovered, n.notified);
  if (!from || !to) return null;
  return from <= to ? { from, to } : { from: to, to: from };
}

const dayNumber = (d: string): number => Date.parse(`${d}T00:00:00Z`) / DAY_MS;

/** The spans overlap, or the gap between them is at most `days` days. */
export function spansClose(a: Span, b: Span, days = 30): boolean {
  const gap = Math.max(dayNumber(a.from), dayNumber(b.from)) - Math.min(dayNumber(a.to), dayNumber(b.to));
  return gap <= days;
}

/** The `companies` row, or null when nothing differs from the stored one. */
export function companyRow(
  key: CompanyKey,
  rawNames: string[],
  stored: Row | undefined,
  hint?: { cik?: string; domain?: string },
): Row | null {
  const first = rawNames.map((n) => n.trim()).find((n) => n !== '');
  const aliases: string[] = [];
  for (const a of [...readList(stored?.aliases), ...rawNames.map(normaliseName)])
    if (a !== '' && !aliases.includes(a) && aliases.length < MAX_ALIASES) aliases.push(a);
  const row: Row = {
    key,
    name: text(stored?.name) ?? (first ?? key).slice(0, 200),
    cik: hint?.cik ?? stored?.cik ?? null,
    domain: hint?.domain ?? stored?.domain ?? null,
    ticker: stored?.ticker ?? null,
    sector: stored?.sector ?? null,
    aliases: JSON.stringify(aliases),
  };
  return differs(row, stored) ? row : null;
}
