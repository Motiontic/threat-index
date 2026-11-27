import { CAPS, clean } from '../clean';
import { arr, bool, COMMON_OUT, int, nstr, obj, root, str } from '../schema';
import { list, rec } from './common';

export const DEEP_TEMPLATES = [
  'cve-history',
  'package-advisories',
  'epss-history',
  'company-breaches',
  'kev-additions',
] as const;
export const ROW_KEY = /^[a-z][a-z0-9_]{0,40}$/;
export const MAX_DEEP_ROWS = 5000;
const MAX_ROW_KEYS = 40;

/**
 * One row of a deep query, as plain data for a model. Every string came from outside sources, so each goes
 * through `clean()`. Keys must look like column names. Numbers and booleans pass; objects and arrays are dropped.
 */
export function deepRow(v: unknown): Record<string, string | number | boolean> | null {
  const out: Record<string, string | number | boolean> = {};
  for (const [k, x] of Object.entries(rec(v))) {
    if (Object.keys(out).length >= MAX_ROW_KEYS) break;
    if (!ROW_KEY.test(k)) continue;
    if (typeof x === 'string') {
      const s = clean(x, CAPS.title);
      if (s !== null) out[k] = s;
    } else if (typeof x === 'number' && Number.isFinite(x)) out[k] = x;
    else if (typeof x === 'boolean') out[k] = x;
  }
  return Object.keys(out).length > 0 ? out : null;
}

export function deepRows(v: unknown): Record<string, string | number | boolean>[] {
  return list(v)
    .slice(0, MAX_DEEP_ROWS)
    .flatMap((r) => {
      const row = deepRow(r);
      return row ? [row] : [];
    });
}

const untrusted = {
  type: 'object',
  patternProperties: { [ROW_KEY.source]: { type: ['string', 'number', 'boolean'], maxLength: CAPS.title } },
  additionalProperties: false,
  maxProperties: MAX_ROW_KEYS,
};

export const DEEP_OUTPUT_SCHEMA = root(
  obj({
    ...COMMON_OUT,
    template: str(40),
    rowCount: int(),
    truncated: bool(),
    rows: arr(obj({ untrusted }), MAX_DEEP_ROWS),
    nextCursor: nstr(512),
  }),
);
