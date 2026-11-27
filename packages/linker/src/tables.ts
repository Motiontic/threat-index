import type { SignalKind } from '@ti/core/types';
import type { ChangeKind } from './detect';

/** Every table and column name the linker writes comes from this file, never from record data. */
export type Row = Record<string, unknown>;

export const ROW_ORDER = [
  'vulns',
  'advisories',
  'signals',
  'techniques',
  'companies',
  'breach_events',
  'breach_notices',
  'incidents',
  // Last, so a partly written batch never holds an alert without its data.
  'changes',
] as const;
export type LinkTable = (typeof ROW_ORDER)[number];

export const PRIMARY_KEYS: Record<LinkTable, readonly string[]> = {
  vulns: ['key'],
  advisories: ['source', 'source_id'],
  signals: ['vuln_key', 'kind', 'source', 'ref'],
  techniques: ['id'],
  companies: ['key'],
  breach_events: ['key'],
  breach_notices: ['source', 'notice_id'],
  incidents: ['source', 'incident_id'],
  changes: ['id'],
};

/** Real column names, in migration order. */
export const COLUMNS: Record<LinkTable, readonly string[]> = {
  vulns: [
    'key',
    'kind',
    'title',
    'summary',
    'published',
    'modified',
    'cvss',
    'cvss_version',
    'cvss_source',
    'cwe',
    'kev_added',
    'kev_due',
    'ransomware',
    'exploit_public',
    'epss',
    'epss_pct',
    'epss_date',
    'epss_model',
    'ai_related',
    'hot',
    'sources',
    'doc_key',
    'cvss_from',
  ],
  advisories: ['source', 'source_id', 'vuln_key', 'status', 'published', 'modified', 'url', 'licence'],
  signals: ['vuln_key', 'kind', 'source', 'ref', 'first_seen', 'evidence_date', 'url'],
  techniques: ['id', 'framework', 'name', 'parent', 'summary'],
  companies: ['key', 'name', 'cik', 'domain', 'ticker', 'sector', 'aliases'],
  breach_events: [
    'key',
    'company_key',
    'first_seen',
    'dates',
    'counts_by_unit',
    'notice_count',
    'confidence',
    'modified',
  ],
  breach_notices: [
    'source',
    'notice_id',
    'company_key',
    'raw_name',
    'occurred_from',
    'occurred_to',
    'discovered',
    'notified',
    'count',
    'count_unit',
    'jurisdiction',
    'data_types',
    'url',
    'event_key',
    'modified',
    'name_key',
  ],
  incidents: [
    'source',
    'incident_id',
    'kind',
    'title',
    'date',
    'entities',
    'techniques',
    'url',
    'gated',
    'modified',
  ],
  changes: ['id', 'entity_key', 'kind', 'old', 'new', 'at', 'source'],
};

/** Reserved advisories.source for the alias map; no source in the registry has this id. */
export const ALIAS_SOURCE = 'alias';
export const KEV_SOURCE = 'cisa-kev';
export const CVE_HOME_SOURCE = 'cve-list';

/** The CHECK lists in the migrations (schema.test.ts keeps these equal to them). */
export const CHANGE_KINDS: readonly ChangeKind[] = [
  'newly_exploited',
  'public_exploit',
  'epss_band',
  'fix_released',
  'cvss_change',
  'breach_notice',
  'new_advisory',
];
export const SIGNAL_KINDS: readonly SignalKind[] = [
  'exploited_wild',
  'public_exploit',
  'detection',
  'poc',
  'ransomware',
];
export const ADVISORY_STATUSES: readonly string[] = ['active', 'withdrawn', 'rejected'];
export const INCIDENT_KINDS: readonly string[] = ['ai', 'cyber_op', 'cyber_event'];

/** A row's primary key as one string, for in-memory indexes. */
export function pkOf(table: LinkTable, row: Row): string {
  return JSON.stringify(PRIMARY_KEYS[table].map((c) => row[c] ?? null));
}

/** Exactly `COLUMNS[table]`, in order, with `undefined` as null. */
export function fullRow(table: LinkTable, row: Row): Row {
  return Object.fromEntries(COLUMNS[table].map((c) => [c, row[c] ?? null]));
}
