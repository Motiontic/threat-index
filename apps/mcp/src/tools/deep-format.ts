import { CAPS, clean } from '../clean';
import { sourceLink } from '../links';
import { arr, bool, COMMON_OUT, int, nstr, obj, root, str } from '../schema';
import { ID_RE, list, matching, rec, VERSION_RE } from './common';

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
export interface AffectedRange {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
}
type Value = Cell | AffectedRange[];
export const MAX_RANGES = 20;
/** Which package a `package-advisories` query asked about: the rows keep only that package's ranges. */
export interface DeepQuery {
  ecosystem?: string;
  package?: string;
}

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
    ['ref', 'ref'],
    ['evidence_date', 'evidenceDate'],
    ['title', 'title'],
    ['summary', 'summary'],
    ['aliases', 'aliases'],
    ['cvss_version', 'cvssVersion'],
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

function cell(x: unknown, cap: number = CAPS.title): Cell | null {
  if (typeof x === 'string') return clean(x, cap);
  if (typeof x === 'number' && Number.isFinite(x)) return x;
  if (typeof x === 'boolean') return x;
  // A list of strings (aliases, data types) is joined into one capped string; anything else is dropped.
  if (Array.isArray(x) && x.length > 0 && x.length <= 200 && x.every((e) => typeof e === 'string'))
    return clean((x as string[]).join(', '), cap);
  return null;
}

/** A signal's `ref` is an ID or a URL. A URL goes through `sourceLink`; anything else that is not an ID is dropped. */
function refCell(x: unknown): string | null {
  if (typeof x !== 'string') return null;
  if (/^https?:/i.test(x)) return sourceLink(x);
  return ID_RE.test(x) ? x : null;
}

/** The version ranges of the queried package, from the record's `affected`. At most 20, version strings only. */
function ranges(affected: unknown, q: DeepQuery | undefined): AffectedRange[] {
  if (!q?.ecosystem || !q.package) return [];
  const eco = q.ecosystem.toLowerCase();
  const out: AffectedRange[] = [];
  for (const a of list(affected)) {
    const r = rec(a);
    if (typeof r.ecosystem !== 'string' || r.ecosystem.toLowerCase() !== eco || r.name !== q.package)
      continue;
    const range: AffectedRange = {};
    const introduced = matching(r.introduced, VERSION_RE);
    const fixed = matching(r.fixed, VERSION_RE);
    const lastAffected = matching(r.lastAffected, VERSION_RE);
    if (introduced) range.introduced = introduced;
    if (fixed) range.fixed = fixed;
    if (lastAffected) range.lastAffected = lastAffected;
    if (Object.keys(range).length > 0) out.push(range);
    if (out.length >= MAX_RANGES) break;
  }
  return out;
}

/**
 * One row of a deep query, as plain data for a model. Every string came from outside sources, so each goes
 * through `clean()`. Only the template's own columns are kept, and their names are fixed here, so a key from the
 * data is never used.
 */
export function deepRow(v: unknown, template: DeepTemplate, query?: DeepQuery): Record<string, Value> | null {
  const row = rec(v);
  const out: Record<string, Value> = {};
  const put = (columns: readonly (readonly [string, string])[], from: Record<string, unknown>) => {
    for (const [key, field] of columns) {
      const c =
        key === 'ref'
          ? refCell(from[field])
          : cell(from[field], key === 'summary' ? CAPS.summary : CAPS.title);
      if (c !== null && c !== '') out[key] = c;
    }
  };
  if (template === 'epss-history') put(EPSS_COLUMNS, row);
  else {
    const source = cell(row.source);
    if (source !== null && source !== '') out.source = source;
    const record = rec(row.record);
    put(COLUMNS[template], record);
    if (template === 'package-advisories') {
      const affected = ranges(record.affected, query);
      if (affected.length > 0) out.affected = affected;
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

export function deepRows(v: unknown, template: DeepTemplate, query?: DeepQuery): Record<string, Value>[] {
  return list(v)
    .slice(0, MAX_DEEP_ROWS)
    .flatMap((r) => {
      const row = deepRow(r, template, query);
      return row ? [row] : [];
    });
}

const untrusted = {
  type: 'object',
  patternProperties: {
    [ROW_KEY.source]: {
      anyOf: [
        { type: ['string', 'number', 'boolean'], maxLength: CAPS.summary },
        {
          type: 'array',
          maxItems: MAX_RANGES,
          items: {
            type: 'object',
            additionalProperties: false,
            maxProperties: 3,
            properties: {
              introduced: { type: 'string', maxLength: 64 },
              fixed: { type: 'string', maxLength: 64 },
              lastAffected: { type: 'string', maxLength: 64 },
            },
          },
        },
      ],
    },
  },
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
