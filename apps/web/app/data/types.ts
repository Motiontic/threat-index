// The shapes the pages use. The wire shapes come from `@ti/core/api`; only web-side shapes live here.
import type { EntryPreview, IndexLetterResponse, SearchResponse, SourcesResponse } from '@ti/core/api';

export type {
  ApiError,
  Credit,
  EntryPreview,
  EntryResponse,
  IndexLetterResponse,
  SearchHit,
  SearchResponse,
  SourceStatus,
  SourcesResponse,
} from '@ti/core/api';

export type EntryType = 'vuln' | 'breach' | 'ai' | 'mal' | 'tech' | 'term';
export type SearchSort = 'rel' | 'new';
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Search parameters after validation: every value is known and bounded. */
export interface SearchParams {
  q?: string;
  type?: EntryType[];
  sig?: 'kev'[];
  sev?: Severity;
  year?: string;
  sort?: SearchSort;
  cursor?: string;
}

/** What every loader calls. Each method is async and may throw `ApiUnavailable` or `ApiBadRequest`. */
export interface SiteData {
  mode: 'api' | 'fixtures';
  entry: (id: string) => Promise<EntryPreview | null>;
  search: (params: SearchParams) => Promise<SearchResponse>;
  index: (letter: string, cursor?: string) => Promise<IndexLetterResponse | null>;
  sources: () => Promise<SourcesResponse>;
  sitemap: () => Promise<Response | null>;
}
