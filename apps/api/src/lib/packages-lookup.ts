/**
 * Reads for POST /v1/packages/check: three D1 round trips whatever the list size (advisories, then vulns and
 * signals side by side), with the licence read alongside. D1 allows 100 bound parameters per statement, so
 * names travel as one JSON array and are opened with `json_each`.
 */
import type { Ecosystem } from '@ti/core/packages';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { type DisplayMap, displayFor, type ReadEnv } from './preview';

export const LOOKUP_CHUNK = 100;

export interface AffectedRecordRow {
  ecosystem: string;
  name: string;
  source: string;
  source_id: string;
  range_no: number;
  vuln_key: string;
  range_type: 'SEMVER' | 'ECOSYSTEM' | 'EXACT';
  introduced: string;
  fixed: string | null;
  last_affected: string | null;
  versions: string | null;
  summary: string | null;
  severity: string | null;
  reviewed: number;
  url: string | null;
  published: string | null;
  modified: string;
}
export interface HotVulnRow {
  key: string;
  kind: string;
  title: string | null;
  cvss: number | null;
  cvss_source: string | null;
  cvss_from: string | null;
  sources: string | null;
  epss: number | null;
  kev_added: string | null;
  ransomware: number;
  exploit_public: number;
}
export interface SignalLookupRow {
  vuln_key: string;
  kind: string;
  source: string;
}
export interface PackageData {
  rows: AffectedRecordRow[];
  vulns: Map<string, HotVulnRow>;
  signals: Map<string, SignalLookupRow[]>;
  display: DisplayMap;
}

export const AFFECTED_SQL = `SELECT a.ecosystem, a.name, a.source, a.source_id, a.range_no, a.vuln_key, a.range_type,
       a.introduced, a.fixed, a.last_affected, a.versions,
       p.summary, p.severity, p.reviewed, p.url, p.published, p.modified
FROM affected a
JOIN package_advisories p ON p.source = a.source AND p.source_id = a.source_id
WHERE a.ecosystem = ?1 AND a.name IN (SELECT value FROM json_each(?2)) AND p.status = 'active'`;
export const VULNS_SQL = `SELECT key, kind, title, cvss, cvss_source, cvss_from, sources, epss, kev_added, ransomware, exploit_public
FROM vulns WHERE key IN (SELECT value FROM json_each(?1))`;
export const SIGNALS_SQL = `SELECT vuln_key, kind, source FROM signals
WHERE vuln_key IN (SELECT value FROM json_each(?1))
  AND kind IN ('exploited_wild','public_exploit','poc','ransomware')`;

function chunks<T>(list: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

async function batchRows<T>(db: D1Database, statements: D1PreparedStatement[]): Promise<T[]> {
  if (statements.length === 0) return [];
  const results = await db.batch<T>(statements);
  return results.flatMap((r) => r.results ?? []);
}

export async function loadPackageData(env: ReadEnv, names: Map<Ecosystem, string[]>): Promise<PackageData> {
  const stmts: D1PreparedStatement[] = [];
  for (const [ecosystem, list] of names) {
    for (const chunk of chunks([...new Set(list)], LOOKUP_CHUNK)) {
      stmts.push(env.DB_ADVISORIES.prepare(AFFECTED_SQL).bind(ecosystem, JSON.stringify(chunk)));
    }
  }
  const rows = await batchRows<AffectedRecordRow>(env.DB_ADVISORIES, stmts);

  const keys = [...new Set(rows.map((r) => r.vuln_key))];
  const keyChunks = chunks(keys, LOOKUP_CHUNK);
  // Signal and CVSS sources aren't known until the reads below return, so the licence read covers every
  // source MTI knows: one bulk KV get, run at the same time as the two batches.
  const sourceIds = [...new Set([...rows.map((r) => r.source), ...SOURCE_BY_ID.keys()])];
  const [vulnRows, signalRows, display] = await Promise.all([
    batchRows<HotVulnRow>(
      env.DB_VULNS,
      keyChunks.map((c) => env.DB_VULNS.prepare(VULNS_SQL).bind(JSON.stringify(c))),
    ),
    batchRows<SignalLookupRow>(
      env.DB_SIGNALS,
      keyChunks.map((c) => env.DB_SIGNALS.prepare(SIGNALS_SQL).bind(JSON.stringify(c))),
    ),
    displayFor(env.SETTINGS, sourceIds),
  ]);

  const vulns = new Map(vulnRows.map((v) => [v.key, v]));
  const signals = new Map<string, SignalLookupRow[]>();
  for (const s of signalRows) {
    const list = signals.get(s.vuln_key);
    if (list) list.push(s);
    else signals.set(s.vuln_key, [s]);
  }
  return { rows, vulns, signals, display };
}
