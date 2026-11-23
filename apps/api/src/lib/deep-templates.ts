/**
 * Deep-query templates and their typed parameters. This file has NO imports on purpose: the Worker and the
 * E2B job both use it (the job imports it by relative path; it moves to @ti/core later).
 * Every parameter is checked against a strict whole-string pattern. Anything else is refused, never escaped.
 */

export type DeepTemplate =
  | 'cve-history'
  | 'package-advisories'
  | 'epss-history'
  | 'company-breaches'
  | 'kev-additions';
export type ParamType = 'cve' | 'ecosystem' | 'package' | 'company' | 'day';
export interface DeepQuery {
  template: DeepTemplate;
  params: Record<string, string>;
}

export const DEEP_TEMPLATES: Record<
  DeepTemplate,
  { params: Record<string, ParamType>; optional?: string[] }
> = {
  'cve-history': { params: { cve: 'cve' } },
  'package-advisories': { params: { ecosystem: 'ecosystem', package: 'package' } },
  'epss-history': { params: { cve: 'cve', from: 'day', to: 'day' }, optional: ['from', 'to'] },
  'company-breaches': { params: { company: 'company' } },
  'kev-additions': { params: { from: 'day', to: 'day' }, optional: ['from', 'to'] },
};

export const MAX_RESULT_ROWS = 1000;
/** Longest `from`..`to` span in days (inclusive). Templates not listed take no day range. */
export const MAX_SPAN_DAYS: Partial<Record<DeepTemplate, number>> = {
  'epss-history': 31,
  'kev-additions': 366,
};

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const ECOSYSTEM_RE = /^[A-Za-z][A-Za-z0-9 .:_-]{0,39}$/;
const PACKAGE_RE = /^[A-Za-z0-9@/._+:-]{1,214}$/;
const CIK_RE = /^cik:\d{1,10}$/;
const HOST_RE = /^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;
const NAME_RE = /^[\p{L}\p{N} .,&'()-]{2,80}$/u;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86_400_000;

/** UTC midnight of a real `YYYY-MM-DD` day in ms, or null. */
function dayMs(day: string): number | null {
  if (!DAY_RE.test(day)) return null;
  const ms = Date.parse(`${day}T00:00:00Z`);
  if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== day) return null;
  return ms;
}
const dayOf = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** The cleaned value for a parameter, or null when it is not acceptable. */
function cleanParam(type: ParamType, raw: string): string | null {
  switch (type) {
    case 'cve': {
      const v = raw.toUpperCase();
      return CVE_RE.test(v) ? v : null;
    }
    case 'ecosystem':
      return ECOSYSTEM_RE.test(raw) ? raw : null;
    case 'package':
      return PACKAGE_RE.test(raw) ? raw : null;
    case 'company': {
      const v = raw.trim();
      if (CIK_RE.test(v)) return v;
      if (v.startsWith('domain:')) {
        const host = v.slice(7);
        return host.length <= 253 && HOST_RE.test(host) ? v : null;
      }
      return NAME_RE.test(v) ? v : null;
    }
    case 'day':
      return dayMs(raw) === null ? null : raw;
  }
}

export function validateDeepQuery(
  input: unknown,
  now: Date = new Date(),
): { ok: true; query: DeepQuery } | { ok: false; field: string } {
  if (typeof input !== 'object' || input === null || Array.isArray(input))
    return { ok: false, field: 'body' };
  const body = input as Record<string, unknown>;
  for (const k of Object.keys(body)) if (k !== 'template' && k !== 'params') return { ok: false, field: k };
  const template = body.template;
  if (typeof template !== 'string' || !Object.hasOwn(DEEP_TEMPLATES, template))
    return { ok: false, field: 'template' };
  const t = template as DeepTemplate;
  const spec = DEEP_TEMPLATES[t];
  const given = body.params;
  if (typeof given !== 'object' || given === null || Array.isArray(given))
    return { ok: false, field: 'params' };
  const p = given as Record<string, unknown>;
  for (const k of Object.keys(p)) if (!Object.hasOwn(spec.params, k)) return { ok: false, field: k };

  const params: Record<string, string> = {};
  for (const [name, type] of Object.entries(spec.params)) {
    const v = Object.hasOwn(p, name) ? p[name] : undefined;
    if (v === undefined) {
      if (spec.optional?.includes(name)) continue;
      return { ok: false, field: name };
    }
    if (typeof v !== 'string') return { ok: false, field: name };
    const clean = cleanParam(type, v);
    if (clean === null) return { ok: false, field: name };
    params[name] = clean;
  }

  const span = MAX_SPAN_DAYS[t];
  if (span !== undefined) {
    const today = dayMs(dayOf(now.getTime())) as number;
    const to = params.to ?? dayOf(today);
    const toMs = dayMs(to) as number;
    if (toMs > today) return { ok: false, field: 'to' };
    const from = params.from ?? dayOf(toMs - (span - 1) * DAY_MS);
    const fromMs = dayMs(from) as number;
    if (fromMs > toMs) return { ok: false, field: 'from' };
    if ((toMs - fromMs) / DAY_MS + 1 > span) return { ok: false, field: params.from ? 'from' : 'to' };
    params.from = from;
    params.to = to;
  }
  return { ok: true, query: { template: t, params } };
}
