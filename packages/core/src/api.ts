import type { DisplayMode } from './licence';

/** Shared JSON shapes for the public API and the web pages. Field names are camelCase. */

export interface Credit {
  sourceId: string;
  name: string;
  text: string;
  url?: string;
}

/** What a visitor may see. Everything else needs a free account. */
export interface EntryPreview {
  key: string; // CVE ID, or the source ID when there is no CVE
  kind: string; // vulns.kind
  title: string;
  summary: string;
  aliases: string[];
  published?: string;
  modified?: string;
  cvss?: number;
  cvssVersion?: string;
  exploited: boolean; // in KEV or another exploited-in-the-wild signal
  kevAdded?: string;
  epss?: number;
  credits: Credit[];
}

export interface EntryAdvisory {
  source: string;
  sourceId: string;
  status: string;
  url?: string;
  published?: string;
  modified?: string;
  display: DisplayMode;
  affected?: { ecosystem: string; name: string; introduced?: string; fixed?: string; range?: string }[];
}
export interface EntrySignal {
  kind: string;
  source: string;
  ref: string;
  firstSeen: string;
  url?: string;
}
export interface EntryChange {
  kind: string;
  old?: string;
  new?: string;
  at: string;
  source?: string;
}

export interface EntryFull extends EntryPreview {
  cwe: string[];
  advisories: EntryAdvisory[];
  signals: EntrySignal[];
  changes: EntryChange[];
}

export type EntryResponse = { access: 'preview'; entry: EntryPreview } | { access: 'full'; entry: EntryFull };

export interface SearchHit {
  key: string;
  title: string;
  summary: string;
  cvss?: number;
  exploited: boolean;
  published?: string;
}
export interface SearchResponse {
  query: string;
  hits: SearchHit[];
  total: number;
  cursor?: string;
  credits: Credit[];
}

export interface IndexLetterResponse {
  letter: string;
  items: { key: string; title: string }[];
  cursor?: string;
}

export interface SourceStatus {
  id: string;
  name: string;
  gives: string;
  pattern: string;
  cadence: string;
  licence: 'on' | 'ask' | 'wait' | 'link';
  display: DisplayMode;
  credit: string;
  lastSuccess?: string;
  lastRunStatus?: string;
}
export interface SourcesResponse {
  sources: SourceStatus[];
}

export interface ApiError {
  error: string;
}
