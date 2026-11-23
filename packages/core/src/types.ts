/** Shared record shapes. Every record names the source it came from. */

export type VulnKind = 'cve' | 'ghsa' | 'osv' | 'mal' | 'euvd' | 'other';

export interface VulnRecord {
  key: string; // CVE ID, or the source ID when there is no CVE
  kind: VulnKind;
  title: string;
  summary: string; // <= 300 chars; long text lives in R2 docs/
  published?: string; // ISO date
  modified: string; // ISO timestamp, used for "newer wins" upserts
  cvss?: number;
  cvssVersion?: string;
  cvssSource?: string; // who gave the score (CNA, NVD, vendor…)
  cwe: string[];
  aliases: string[];
  source: string;
}

export interface Affected {
  ecosystem: string; // PyPI, npm, Maven, Debian:12, vendor product…
  name: string;
  introduced?: string;
  fixed?: string;
  range?: string; // human-readable when versions are not machine-comparable
}

export interface AdvisoryRecord {
  source: string;
  sourceId: string;
  vulnKey: string | null;
  status: 'active' | 'withdrawn' | 'rejected';
  published?: string;
  modified: string;
  url?: string;
  affected?: Affected[];
}

/** Kept separate on purpose: never merge these into one "exploited" flag. */
export type SignalKind = 'exploited_wild' | 'public_exploit' | 'detection' | 'poc' | 'ransomware';

export interface SignalRecord {
  vulnKey: string;
  kind: SignalKind;
  source: string;
  ref: string; // e.g. KEV entry, EDB-ID, module path, template ID
  firstSeen: string;
  evidenceDate?: string;
  url?: string;
}

export type CountUnit = 'state_residents' | 'individuals' | 'accounts' | 'not_stated' | 'claim';

export interface NoticeRecord {
  source: string;
  noticeId: string;
  rawName: string;
  companyKey?: string;
  occurredFrom?: string;
  occurredTo?: string;
  discovered?: string;
  notified?: string;
  count?: number;
  countUnit: CountUnit; // counts in different units are never added together
  jurisdiction?: string;
  dataTypes?: string[];
  url?: string;
}

export interface IncidentRecord {
  source: string;
  incidentId: string;
  kind: 'ai' | 'cyber_op' | 'cyber_event';
  title: string;
  date?: string;
  entities?: string[];
  techniques?: string[];
  url?: string;
}

export interface TechniqueRecord {
  id: string; // T1190, AML.T0051, CWE-306, CAPEC-66
  framework: 'attack' | 'atlas' | 'cwe' | 'capec';
  name: string;
  parent?: string;
  summary?: string;
}

export interface Cursor {
  kind: 'commit' | 'timestamp' | 'etag' | 'version';
  value: string;
  etag?: string;
}

export interface Receipt {
  source: string;
  runId: string;
  fetchedAt: string;
  contentType: string;
  body: ArrayBuffer | string;
}

export interface ParseResult<T> {
  records: T[];
  /** Fields we did not expect. Reported by the watchdog, never a crash. */
  unknownFields: string[];
}

/** Anything a parser can emit. Each record names the source it came from. */
export type ParsedRecord =
  | VulnRecord
  | AdvisoryRecord
  | SignalRecord
  | NoticeRecord
  | IncidentRecord
  | TechniqueRecord;
