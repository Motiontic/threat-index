import type { InboxRow } from '@ti/core/inbox';
import type { SignalRecord } from '@ti/core/types';
import { AFFECTED_COLUMNS, AFFECTED_KEY, PACKAGE_ADVISORY_COLUMNS } from '../affected';
import type { LinkDeps } from '../link';
import { COLUMNS, type LinkTable, PRIMARY_KEYS, pkOf, type Row } from '../tables';

/** NOT NULL columns without a default, per the migrations (schema.test.ts checks COLUMNS covers them). */
const REQUIRED: Record<LinkTable, readonly string[]> = {
  vulns: ['key', 'kind', 'title', 'modified'],
  advisories: ['source', 'source_id', 'status', 'modified'],
  signals: ['vuln_key', 'kind', 'source', 'ref', 'first_seen'],
  techniques: ['id', 'framework', 'name'],
  companies: ['key', 'name'],
  breach_events: ['key', 'first_seen', 'modified'],
  breach_notices: ['source', 'notice_id', 'raw_name', 'count_unit', 'modified'],
  incidents: ['source', 'incident_id', 'kind', 'title', 'modified'],
  changes: ['id', 'entity_key', 'kind', 'at'],
};

export const NOW = new Date('2026-03-01T12:00:00.000Z');

export type PackageTable = 'package_advisories' | 'affected';
const PKG_KEYS: Record<PackageTable, readonly string[]> = {
  package_advisories: ['source', 'source_id'],
  affected: AFFECTED_KEY,
};
const PKG_COLUMNS: Record<PackageTable, readonly string[]> = {
  package_advisories: PACKAGE_ADVISORY_COLUMNS,
  affected: AFFECTED_COLUMNS,
};
const isPkg = (t: string): t is PackageTable => t === 'package_advisories' || t === 'affected';
const pkKey = (t: PackageTable, row: Row) => JSON.stringify(PKG_KEYS[t].map((c) => row[c]));

export interface Fake {
  /** Stored package rows. */
  pkg: Record<PackageTable, Map<string, Row>>;
  deps: LinkDeps;
  tables: Record<LinkTable, Map<string, Row>>;
  reads: { table: string; keys: Row[] }[];
  coldCalls: string[];
  cold: Map<string, Row>;
  put(table: LinkTable, row: Row): void;
  apply(rows: InboxRow[]): void;
  all(table: LinkTable): Row[];
}

export function makeFake(): Fake {
  const tables = Object.fromEntries(
    (Object.keys(COLUMNS) as LinkTable[]).map((t) => [t, new Map<string, Row>()]),
  ) as Fake['tables'];
  const pkg: Fake['pkg'] = { package_advisories: new Map(), affected: new Map() };
  const reads: Fake['reads'] = [];
  const coldCalls: string[] = [];
  const cold = new Map<string, Row>();
  let n = 0;

  const fake: Fake = {
    pkg,
    tables,
    reads,
    coldCalls,
    cold,
    put: (table, row) => {
      tables[table].set(pkOf(table, row), row);
    },
    all: (table) => [...tables[table].values()],
    apply(rows) {
      for (const { table, op, row } of rows) {
        if (isPkg(table)) {
          if (op === 'delete') {
            if (JSON.stringify(Object.keys(row)) !== JSON.stringify(PKG_KEYS[table]))
              throw new Error(`delete on ${table} must carry exactly its key`);
            pkg[table].delete(pkKey(table, row));
          } else {
            if (JSON.stringify(Object.keys(row)) !== JSON.stringify(PKG_COLUMNS[table]))
              throw new Error(`upsert on ${table} must carry exactly its columns`);
            pkg[table].set(pkKey(table, row), row);
          }
          continue;
        }
        const t = table as LinkTable;
        if (!COLUMNS[t]) throw new Error(`unknown table ${table}`);
        if (op === 'delete') {
          if (JSON.stringify(Object.keys(row)) !== JSON.stringify(PRIMARY_KEYS[t]))
            throw new Error(`delete on ${table} must carry exactly ${PRIMARY_KEYS[t]}`);
          tables[t].delete(pkOf(t, row));
          continue;
        }
        if (JSON.stringify(Object.keys(row)) !== JSON.stringify(COLUMNS[t]))
          throw new Error(`upsert on ${table} must carry exactly its columns, got ${Object.keys(row)}`);
        for (const c of REQUIRED[t]) if (row[c] === null) throw new Error(`${table}.${c} is NOT NULL`);
        tables[t].set(pkOf(t, row), row);
      }
    },
    deps: {
      async read(table, keys) {
        if (keys.length === 0) throw new Error(`read(${table}) with no keys`);
        reads.push({ table, keys });
        if (isPkg(table))
          return [...pkg[table].values()].filter((row) =>
            keys.some((k) => Object.entries(k).every(([c, v]) => row[c] === v)),
          );
        const t = table as LinkTable;
        return [...tables[t].values()].filter((row) =>
          keys.some((k) => Object.entries(k).every(([c, v]) => row[c] === v)),
        );
      },
      async lookupCold(key) {
        coldCalls.push(key);
        return cold.get(key) ?? null;
      },
      now: () => NOW,
      newId: () => `id-${++n}`,
    },
  };
  return fake;
}

/** What `parseKev` emits for fixtures/cisa-kev/sample.json (CVE-2025-3248, added 2025-05-05). */
export const KEV_EXPLOITED: SignalRecord = {
  vulnKey: 'CVE-2025-3248',
  kind: 'exploited_wild',
  source: 'cisa-kev',
  ref: 'CVE-2025-3248',
  firstSeen: '2025-05-05',
  evidenceDate: '2025-05-05',
};
/** The ransomware signal `parseKev` adds when CISA marks known ransomware use. */
export const KEV_RANSOMWARE: SignalRecord = {
  vulnKey: 'CVE-2025-3248',
  kind: 'ransomware',
  source: 'cisa-kev',
  ref: 'CVE-2025-3248',
  firstSeen: '2025-05-05',
};

/** A stored, hot `vulns` row. */
export function vulnRow(key: string, over: Row = {}): Row {
  return {
    key,
    kind: key.startsWith('CVE-') ? 'cve' : 'ghsa',
    title: `Title ${key}`,
    summary: 'Summary.',
    published: '2025-03-01',
    modified: '2026-01-01T00:00:00.000Z',
    cvss: null,
    cvss_version: null,
    cvss_source: null,
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
    sources: '["cve-list"]',
    doc_key: `docs/vuln/${key}.json`,
    ...over,
  };
}
