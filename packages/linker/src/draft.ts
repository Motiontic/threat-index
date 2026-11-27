import { isCve } from '@ti/core/ids';
import { jsonList, readList } from './clean';
import type { ChangeKind, VulnState } from './detect';
import { COLUMNS, type Row } from './tables';

type ColType = 'text' | 'real' | 'int';

/** The primitive type each `vulns` column holds, so a cold summary can't plant a wrong-typed value. */
const VULN_TYPES: Record<string, ColType> = {
  key: 'text',
  kind: 'text',
  title: 'text',
  summary: 'text',
  published: 'text',
  modified: 'text',
  cvss: 'real',
  cvss_version: 'text',
  cvss_source: 'text',
  cvss_from: 'text',
  cwe: 'text',
  kev_added: 'text',
  kev_due: 'text',
  ransomware: 'int',
  exploit_public: 'int',
  epss: 'real',
  epss_pct: 'real',
  epss_date: 'text',
  epss_model: 'text',
  ai_related: 'int',
  hot: 'int',
  sources: 'text',
  doc_key: 'text',
};

const NEVER_FROM_SUMMARY = new Set(['key', 'modified', 'hot', 'doc_key']);

function rightType(col: string, v: unknown): boolean {
  switch (VULN_TYPES[col]) {
    case 'text':
      return typeof v === 'string';
    case 'real':
      return typeof v === 'number' && Number.isFinite(v);
    case 'int':
      return typeof v === 'number' && Number.isInteger(v);
    default:
      return false;
  }
}

export interface VulnDraft {
  /** Hub key. */
  key: string;
  /** Stored row, merged alias row, promotion summary, or null for an empty start. */
  base: Row | null;
  /** The `vulns` row being built (every column). */
  row: Row;
  before: VulnState | null;
  promoted: boolean;
  /** True when `base` came from D1 (a stored row or a merged alias row). */
  fromD1: boolean;
  /** Source of the first new advisory that lists a fix. */
  fixSource: string | null;
  /** Source of the record behind each change kind. */
  changeSource: Partial<Record<ChangeKind, string>>;
  attached: number;
}

export function emptyVulnRow(key: string): Row {
  return {
    key,
    kind: isCve(key) ? 'cve' : 'other',
    title: key,
    summary: null,
    published: null,
    modified: '',
    cvss: null,
    cvss_version: null,
    cvss_source: null,
    cvss_from: null,
    cwe: '[]',
    kev_added: null,
    kev_due: null,
    ransomware: 0,
    exploit_public: 0,
    epss: null,
    epss_pct: null,
    epss_date: null,
    epss_model: null,
    ai_related: 0,
    hot: 1,
    sources: '[]',
    doc_key: null,
  };
}

/** A stored row onto the defaults: only real columns, and a null in a NOT NULL column falls back. */
export function baseFromStored(key: string, stored: Row): Row {
  const row = emptyVulnRow(key);
  for (const c of COLUMNS.vulns) if (stored[c] !== undefined && stored[c] !== null) row[c] = stored[c];
  row.key = key;
  return row;
}

/** The promotion summary onto the defaults: only columns of the right primitive type. */
export function baseFromSummary(key: string, summary: Row): Row {
  const row = emptyVulnRow(key);
  for (const c of COLUMNS.vulns) {
    if (NEVER_FROM_SUMMARY.has(c)) continue;
    if (rightType(c, summary[c])) row[c] = summary[c];
  }
  return row;
}

export function newDraft(key: string, base: Row | null): VulnDraft {
  return {
    key,
    base,
    row: { ...emptyVulnRow(key), ...(base ?? {}), key },
    before: base ? toVulnState(base) : null,
    promoted: false,
    fromD1: false,
    fixSource: null,
    changeSource: {},
    attached: 0,
  };
}

export function toVulnState(row: Row): VulnState {
  return {
    key: String(row.key),
    kevAdded: typeof row.kev_added === 'string' ? row.kev_added : null,
    exploitPublic: row.exploit_public === 1,
    cvss: typeof row.cvss === 'number' ? row.cvss : null,
    fixed: false,
  };
}

/** Counts the record and adds its source to `sources`. */
export function attach(d: VulnDraft, source: string): void {
  d.attached++;
  d.row.sources = jsonList([...readList(d.row.sources), source]);
}

const earliest = (a: unknown, b: unknown): string | null => {
  const x = typeof a === 'string' ? a : null;
  const y = typeof b === 'string' ? b : null;
  if (x && y) return [x, y].sort()[0] ?? x;
  return x ?? y;
};

const lacks = (key: string, col: string, v: unknown): boolean =>
  v === null ||
  v === undefined ||
  v === '' ||
  (col === 'title' && v === key) ||
  (col === 'kind' && v === 'other');

/** Folds `other` (an alias key's row) into `hub`: fill what the hub lacks, earliest KEV, OR flags, union lists. */
export function mergeVulnRows(hub: Row, other: Row): Row {
  const key = String(hub.key);
  const out: Row = { ...hub };
  const special = new Set([
    'key',
    'modified',
    'hot',
    'doc_key',
    'kev_added',
    'ransomware',
    'exploit_public',
    'ai_related',
    'sources',
    'cwe',
    'cvss',
    'cvss_version',
    'cvss_source',
    'cvss_from',
  ]);
  for (const c of COLUMNS.vulns) {
    if (!special.has(c) && lacks(key, c, out[c]) && !lacks(key, c, other[c])) out[c] = other[c];
  }
  if (out.cvss === null || out.cvss === undefined) {
    out.cvss = other.cvss ?? null;
    out.cvss_version = other.cvss_version ?? null;
    out.cvss_source = other.cvss_source ?? null;
    out.cvss_from = other.cvss_from ?? null;
  }
  out.kev_added = earliest(out.kev_added, other.kev_added);
  for (const f of ['ransomware', 'exploit_public', 'ai_related']) {
    out[f] = out[f] === 1 || other[f] === 1 ? 1 : 0;
  }
  out.sources = jsonList([...readList(out.sources), ...readList(other.sources)]);
  out.cwe = jsonList([...readList(out.cwe), ...readList(other.cwe)]);
  return out;
}

export { earliest };
