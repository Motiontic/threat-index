import type { Credit } from '@ti/core/api';
import { CAPS, clean } from '../clean';
import { sourceLink } from '../links';

export const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
export const SRC_RE = /^[a-z0-9_-]{1,64}$/;
export const DATE_RE = /^\d{4}-\d{2}-\d{2}/;
export const VERSION_RE = /^[A-Za-z0-9.+~:_-]{1,64}$/;

export const date = (v: unknown): string | null =>
  typeof v === 'string' && v.length <= 40 && DATE_RE.test(v) ? v : null;
export const numOrNull = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
export const matching = (v: unknown, re: RegExp): string | null => (typeof v === 'string' && re.test(v) ? v : null);
export const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
export const rec = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
export const sources = (v: unknown): string[] =>
  list(v).filter((s): s is string => typeof s === 'string' && SRC_RE.test(s)).slice(0, 20);

export function credits(v: unknown): { source: string; text: string; url: string | null }[] {
  const out: { source: string; text: string; url: string | null }[] = [];
  for (const c of list(v).slice(0, 20) as Partial<Credit>[]) {
    const source = matching(c?.sourceId, SRC_RE);
    const text = clean(c?.text, CAPS.title);
    if (!source || !text) continue;
    out.push({ source, text, url: sourceLink(c?.url) });
  }
  return out;
}
