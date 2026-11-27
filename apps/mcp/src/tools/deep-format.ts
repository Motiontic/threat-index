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

export type DeepTemplate = (typeof DEEP_TEMPLATES)[number];
type Cell = string | number | boolean;

/**
 * The columns each template keeps, as `[output key, field of the record]`. A row from the job is
 * `{ source, jobId, record }` where `record` is the lake record (a vulnerability, advisory, signal or notice);
 * `epss-history` rows are flat. Only these fields go out, flattened one level. `jobId` never does.
 */
const COLUMNS: Record<Exclude<DeepTemplate, 'epss-history'>, readonly (readonly [string, string])[]> = {
  'cve-history': [
    ['key', 'key'],
    ['source_id', 'sourceId'],
    ['vuln_key', 'vulnKey'],
    ['kind', 'kind'],
    ['title', 'title'],
    ['summary', 'summary'],
    ['aliases', 'aliases'],
    ['published', 'published'],
    ['modified', 'modified'],
    ['first_seen', 'firstSeen'],
    ['severity', 'severity'],
    ['cvss', 'cvss'],
    ['status', 'status'],
  ],
  'package-advisories': [
    ['source_id', 'sourceId'],
    ['vuln_key', 'vulnKey'],
    ['summary', 'summary'],
    ['severity', 'severity'],
    ['published', 'published'],
    ['modified', 'modified'],
    ['status', 'status'],
  ],
  'company-breaches': [
    ['notice_id', 'noticeId'],
    ['company', 'rawName'],
    ['company_key', 'companyKey'],
    ['records', 'count'],
    ['count_unit', 'countUnit'],
    ['occurred_from', 'occurredFrom'],
    ['occurred_to', 'occurredTo'],
    ['discovered', 'discovered'],
    ['notified', 'notified'],
    ['jurisdiction', 'jurisdiction'],
  ],
  'kev-additions': [
    ['vuln_key', 'vulnKey'],
    ['kind', 'kind'],
    ['ref', 'ref'],
    ['first_seen', 'firstSeen'],
    ['evidence_date', 'evidenceDate'],
  ],
};
const EPSS_COLUMNS: readonly (readonly [string, string])[] = [
  ['day', 'day'],
  ['epss', 'epss'],
  ['percentile', 'percentile'],
  ['model', 'model'],
];

function cell(x: unknown): Cell | null {
  if (typeof x === 'string') return clean(x, CAPS.title);
  if (typeof x === 'number' && Number.isFinite(x)) return x;
  if (typeof x === 'boolean') return x;
  // A list of strings (aliases, data types) is joined into one capped string; anything else is dropped.
  if (Array.isArray(x) && x.length > 0 && x.length <= 200 && x.every((e) => typeof e === 'string'))
    return clean((x as string[]).join(', '), CAPS.title);
  return null;
}

/**
 * One row of a deep query, as plain data for a model. Every string came from outside sources, so each goes
 * through `clean()`. Only the template's own columns are kept, and their names are fixed here, so a key from the
 * data is never used.
 */
export function deepRow(v: unknown, template: DeepTemplate): Record<string, Cell> | null {
  const row = rec(v);
  const out: Record<string, Cell> = {};
  const put = (columns: readonly (readonly [string, string])[], from: Record<string, unknown>) => {
    for (const [key, field] of columns) {
      const c = cell(from[field]);
      if (c !== null && c !== '') out[key] = c;
    }
  };
  if (template === 'epss-history') put(EPSS_COLUMNS, row);
  else {
    const source = cell(row.source);
    if (source !== null && source !== '') out.source = source;
    put(COLUMNS[template], rec(row.record));
  }
  return Object.keys(out).length > 0 ? out : null;
}

export function deepRows(v: unknown, template: DeepTemplate): Record<string, Cell>[] {
  return list(v)
    .slice(0, MAX_DEEP_ROWS)
    .flatMap((r) => {
      const row = deepRow(r, template);
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
