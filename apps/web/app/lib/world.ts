// Validation of the visitor's query string for the world list pages, and the wording of breach counts.
import type { CountUnit, WorldQuery } from '../data/types';

export const MAX_WORLD_Q = 100;
export const MAX_WORLD_PAGE = 40;
export const INCIDENT_KINDS = ['ai', 'cyber_op', 'cyber_event', 'cyber'] as const;
export const FRAMEWORKS = ['attack', 'atlas', 'cwe', 'capec'] as const;

// biome-ignore lint/suspicious/noControlCharactersInRegex: strips control characters from the visitor's text
const CONTROL = /[\u0000-\u001f\u007f]/g;

export interface WorldParams extends WorldQuery {
  page: number;
}

/** Known values only, in a fixed order; anything else is dropped. */
export function parseWorldParams(
  qs: URLSearchParams,
  allowed: { kind?: readonly string[]; framework?: readonly string[] } = {},
): WorldParams {
  const out: WorldParams = { page: 1 };
  const q = (qs.get('q') ?? '').replace(CONTROL, ' ').trim().slice(0, MAX_WORLD_Q).trim();
  if (q) out.q = q;
  const rawPage = qs.get('page');
  if (rawPage && /^\d{1,3}$/.test(rawPage)) {
    const n = Number(rawPage);
    if (n >= 1 && n <= MAX_WORLD_PAGE) out.page = n;
  }
  for (const field of ['kind', 'framework'] as const) {
    const list = allowed[field];
    if (!list) continue;
    const wanted = qs.getAll(field);
    const picked = list.filter((v) => wanted.includes(v));
    if (picked.length > 0) out[field] = [...picked];
  }
  return out;
}

/** The `?…` string for a list link, in a fixed order. `page` 1 is left out. */
export function worldHref(path: string, p: WorldQuery, page?: number): string {
  const qs = new URLSearchParams();
  if (p.q) qs.set('q', p.q);
  if (page && page > 1) qs.set('page', String(page));
  for (const k of p.kind ?? []) qs.append('kind', k);
  for (const f of p.framework ?? []) qs.append('framework', f);
  const text = qs.toString();
  return text ? `${path}?${text}` : path;
}

const nf = new Intl.NumberFormat('en-US');
export const formatCount = (n: number): string => nf.format(n);

const UNIT_WORDS: Record<Exclude<CountUnit, 'not_stated' | 'claim'>, [string, string]> = {
  state_residents: ['state resident', 'state residents'],
  individuals: ['individual', 'individuals'],
  accounts: ['account', 'accounts'],
};

/** One line for one count: its own unit and jurisdiction, never added to another. */
export function countLine(c: { unit: CountUnit; jurisdiction: string | null; count: number }): string {
  const where = c.jurisdiction ? ` · ${c.jurisdiction}` : '';
  if (c.unit === 'not_stated') return 'Count not stated';
  if (c.unit === 'claim') return `Claimed by attacker: ${formatCount(c.count)}${where}`;
  const [one, many] = UNIT_WORDS[c.unit];
  return `${formatCount(c.count)} ${c.count === 1 ? one : many}${where}`;
}

export const KIND_LABELS = {
  ai: 'AI incident',
  cyber_op: 'Cyber operation',
  cyber_event: 'Cyber event',
} as const;
export const FRAMEWORK_LABELS = { attack: 'ATT&CK', atlas: 'ATLAS', cwe: 'CWE', capec: 'CAPEC' } as const;

export const pluralise = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;
