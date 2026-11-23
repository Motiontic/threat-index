// Mirrors the ti-api shapes the site will read. `EntryPreview` is what a signed-out visitor gets from
// `GET /v1/entries/:id` (key, kind, title, summary, published, cvss, kev_added) plus display fields
// (`type`, `subtitle`, `aliases`) that the API work still has to confirm.

export type EntryType = 'vuln' | 'breach' | 'ai' | 'mal' | 'tech' | 'term';

export interface EntryPreview {
  key: string;
  type: EntryType;
  title: string;
  subtitle: string;
  summary: string;
  aliases: string[];
  /** ISO date (`2025-04-07`), or null for records without one (techniques, terms). */
  published: string | null;
  cvss: number | null;
  /** ISO date the entry was added to CISA KEV, or null. */
  kev_added: string | null;
}

export interface EntryResponse {
  access: 'preview';
  entry: EntryPreview;
  credits: string[];
}

export type SearchSort = 'rel' | 'new';

export interface SearchParams {
  q: string;
  type: string[];
  sig: string[];
  sort: SearchSort;
}

export interface SearchResult {
  params: SearchParams;
  total: number;
  results: EntryPreview[];
}

export interface IndexBucket {
  letter: string;
  count: number;
  entries: EntryPreview[];
}

export interface IndexResult {
  letter: string | null;
  buckets: IndexBucket[];
}

export type LicenceFilter = 'on' | 'ask' | 'wait' | 'link';

export interface SourceRow {
  id: string;
  name: string;
  gives: string;
  /** Plain-words way in (how the source is fetched). */
  wayIn: string;
  cadence: string;
  licence: LicenceFilter;
  /** Sample last-success time (ISO), or null for sources that are off. */
  lastSuccess: string | null;
}

export interface SourcesResult {
  status: LicenceFilter | null;
  counts: Record<LicenceFilter, number> & { all: number };
  rows: SourceRow[];
}

export interface HomeData {
  tiles: { type: EntryType | 'kev'; label: string; count: number }[];
  kev: EntryPreview[];
  breaches: EntryPreview[];
  changes: { date: string; key: string; text: string }[];
}

export interface SiteData {
  home: () => HomeData;
  search: (params: Partial<SearchParams>) => SearchResult;
  entry: (id: string) => EntryResponse | null;
  index: (letter?: string | null) => IndexResult;
  sources: (status?: string | null) => SourcesResult;
}
