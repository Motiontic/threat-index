import type { InboxRow } from '@ti/core/inbox';
import { canonicalEcosystem, normaliseName } from '@ti/core/packages';
import type { AdvisoryRecord, Affected } from '@ti/core/types';
import { httpUrl, isoDate, text, vulnId } from './clean';

/**
 * Package rows (`affected`, `package_advisories`) for one advisory record. Pure code: the linker and the
 * `affected-backfill` job both call `affectedRows` and `packageWrites`, so the same record gives the same rows.
 */

type Row = Record<string, unknown>;

export const AFFECTED_COLUMNS = [
  'ecosystem',
  'name',
  'source',
  'source_id',
  'range_no',
  'vuln_key',
  'range_type',
  'introduced',
  'fixed',
  'last_affected',
  'versions',
] as const;
export const AFFECTED_KEY = ['ecosystem', 'name', 'source', 'source_id', 'range_no'] as const;
export const PACKAGE_ADVISORY_COLUMNS = [
  'source',
  'source_id',
  'vuln_key',
  'status',
  'summary',
  'severity',
  'reviewed',
  'url',
  'published',
  'modified',
] as const;
/** Meter units per row: 1 + secondary indexes in migrations 0002 and 0003 (the loader test checks this against planWrites). */
export const ROW_COST = { affected: 4, package_advisories: 2 } as const;
export const MAX_EXACT_VERSIONS = 1000;

export type SkipReason = 'no_range_type' | 'git_range' | 'unknown_ecosystem' | 'bad_name' | 'bad_version';

export interface PackagePlan {
  /** Distinct (ecosystem, name) pairs that survived the checks. */
  names: number;
  /** The package_advisories row. Built for every record; written only as packageWrites decides. */
  advisory: Row;
  /** Full affected rows with range_no set. Empty for withdrawn and rejected records. */
  ranges: Row[];
  skipped: Partial<Record<SkipReason, number>>;
}

const OS_ECOSYSTEMS = new Set(['Debian', 'Ubuntu', 'Alpine']);
const OS_SUFFIX = /^[A-Za-z0-9._:-]{1,64}$/;
const VERSION = /^[\x21-\x7e]{1,128}$/;
const SUMMARY_MAX = 300;
const SEVERITY_MAX = 16;

function ecosystemOf(raw: string): string | null {
  const colon = raw.indexOf(':');
  const base = canonicalEcosystem(colon === -1 ? raw : raw.slice(0, colon));
  if (!base) return null;
  if (colon === -1) return base;
  if (!OS_ECOSYSTEMS.has(base)) return null;
  const full = `${base}${raw.slice(colon)}`;
  return OS_SUFFIX.test(full) ? full : null;
}

function plainSummary(raw: unknown): string | null {
  const t = text(raw);
  if (t === null) return null;
  const s = t.replace(/\s+/g, ' ').trim();
  if (s === '') return null;
  if (s.length <= SUMMARY_MAX) return s;
  let out = s.slice(0, SUMMARY_MAX);
  const last = out.charCodeAt(out.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1);
  return out;
}

/** Same record, same rows: the linker and the backfill write identical rows. */
export function affectedRows(r: AdvisoryRecord): PackagePlan {
  const skipped: Partial<Record<SkipReason, number>> = {};
  const skip = (why: SkipReason) => {
    skipped[why] = (skipped[why] ?? 0) + 1;
  };
  const sourceId = vulnId(r.sourceId);
  const source = text(r.source);
  const modified = typeof r.modified === 'string' && r.modified !== '' ? r.modified : null;
  const vulnKey = vulnId(r.vulnKey ?? r.sourceId) ?? sourceId;
  if (!sourceId || !source || !modified || !vulnKey) {
    return { names: 0, advisory: {}, ranges: [], skipped };
  }
  const severity = text(r.severity)?.trim().slice(0, SEVERITY_MAX) || null;
  const advisory: Row = {
    source,
    source_id: sourceId,
    vuln_key: vulnKey,
    status: r.status,
    summary: plainSummary(r.summary),
    severity,
    reviewed: r.reviewed === true ? 1 : 0,
    url: r.url === undefined ? null : httpUrl(r.url),
    published: isoDate(r.published),
    modified,
  };

  const next = new Map<string, number>();
  const seen = new Set<string>();
  const ranges: Row[] = [];
  const names = new Set<string>();
  for (const a of (r.affected ?? []) as Affected[]) {
    if (!a || typeof a !== 'object') continue;
    if (a.rangeType !== 'SEMVER' && a.rangeType !== 'ECOSYSTEM' && a.rangeType !== 'EXACT') {
      skip('no_range_type');
      continue;
    }
    const ecosystem = typeof a.ecosystem === 'string' ? ecosystemOf(a.ecosystem) : null;
    if (!ecosystem) {
      skip('unknown_ecosystem');
      continue;
    }
    const base = canonicalEcosystem(ecosystem.split(':')[0] as string);
    const name = base && typeof a.name === 'string' ? normaliseName(base, a.name) : null;
    if (!name) {
      skip('bad_name');
      continue;
    }
    const introduced = a.introduced ?? '0';
    const list = a.rangeType === 'EXACT' ? a.versions : undefined;
    const versionsOk =
      a.rangeType !== 'EXACT' ||
      (Array.isArray(list) && list.length > 0 && list.length <= MAX_EXACT_VERSIONS && list.every(good));
    const bounds = [introduced, a.fixed, a.lastAffected];
    if (!versionsOk || !bounds.every((v) => v === undefined || good(v))) {
      skip('bad_version');
      continue;
    }
    const pair = JSON.stringify([ecosystem, name]);
    const row: Row = {
      ecosystem,
      name,
      source,
      source_id: sourceId,
      range_no: 0,
      vuln_key: vulnKey,
      range_type: a.rangeType,
      introduced,
      fixed: a.fixed ?? null,
      last_affected: a.lastAffected ?? null,
      versions: list ? JSON.stringify(list) : null,
    };
    const { range_no: _n, ...content } = row;
    const identity = JSON.stringify([pair, content]);
    if (seen.has(identity)) continue;
    seen.add(identity);
    names.add(pair);
    row.range_no = next.get(pair) ?? 0;
    next.set(pair, (row.range_no as number) + 1);
    ranges.push(row);
  }
  return {
    names: names.size,
    advisory,
    ranges: r.status === 'active' ? ranges : [],
    skipped,
  };
}

function good(v: unknown): boolean {
  return typeof v === 'string' && VERSION.test(v);
}

export interface StoredPackageRows {
  advisory?: Row; // the stored package_advisories row, if any
  ranges: Row[]; // the record's stored affected rows (key columns are enough)
}

const keyOf = (row: Row): string => JSON.stringify(AFFECTED_KEY.map((c) => row[c]));

/**
 * The inbox rows for one record, in this order: affected upserts, affected deletes, then the
 * package_advisories upsert.
 * - Nothing when the stored advisory row's `modified` is the same or newer.
 * - Nothing when no package survived and there is no stored row.
 * - Otherwise: the plan's ranges, a delete for each stored range key the plan no longer has, and the advisory row.
 */
export function packageWrites(r: AdvisoryRecord, plan: PackagePlan, stored: StoredPackageRows): InboxRow[] {
  const advisory = plan.advisory;
  if (typeof advisory.source_id !== 'string') return [];
  const storedModified = stored.advisory?.modified;
  if (typeof storedModified === 'string' && storedModified >= (advisory.modified as string)) return [];
  if (plan.names === 0 && !stored.advisory) return [];
  void r;
  const out: InboxRow[] = plan.ranges.map((row) => ({ table: 'affected', op: 'upsert', row }));
  const keep = new Set(plan.ranges.map(keyOf));
  const gone = new Set<string>();
  for (const old of stored.ranges) {
    const k = keyOf(old);
    if (keep.has(k) || gone.has(k)) continue;
    gone.add(k);
    out.push({
      table: 'affected',
      op: 'delete',
      row: Object.fromEntries(AFFECTED_KEY.map((c) => [c, old[c]])),
    });
  }
  out.push({ table: 'package_advisories', op: 'upsert', row: advisory });
  return out;
}

export function packageCost(rows: readonly InboxRow[]): number {
  let units = 0;
  for (const row of rows) units += ROW_COST[row.table as keyof typeof ROW_COST] ?? 0;
  return units;
}
