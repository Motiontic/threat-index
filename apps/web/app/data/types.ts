// The shapes the pages use. The wire shapes come from `@ti/core/api`; only web-side shapes live here.
import type {
  DeleteAccountResponse,
  Me,
  MePatch,
  SavedSearch,
  SavedSearchCreate,
  SavedSearchListResponse,
  WatchItem,
  WatchListResponse,
} from '@ti/core/account';
import type {
  EntryAdvisory,
  EntryChange,
  EntryPreview,
  EntrySignal,
  IndexLetterResponse,
  SearchResponse,
  SourcesResponse,
} from '@ti/core/api';

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

import type {
  BreachDetail,
  BreachSummary,
  IncidentDetail,
  IncidentSummary,
  TechniqueDetail,
  TechniqueSummary,
  WorldList,
} from '@ti/core/world-api';

export type {
  BreachCount,
  BreachDetail,
  BreachNotice,
  BreachSummary,
  CountUnit,
  Framework,
  IncidentDetail,
  IncidentKind,
  IncidentSummary,
  TechniqueDetail,
  TechniqueSummary,
  WorldList,
} from '@ti/core/world-api';

/** A world list query after validation. `kind` and `framework` are values the API accepts. */
export interface WorldQuery {
  q?: string;
  page?: number;
  kind?: string[];
  framework?: string[];
}

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
  breaches: (query: WorldQuery) => Promise<WorldList<BreachSummary>>;
  breach: (key: string) => Promise<BreachDetail | null>;
  incidents: (query: WorldQuery) => Promise<WorldList<IncidentSummary>>;
  incident: (source: string, id: string) => Promise<IncidentDetail | null>;
  techniques: (query: WorldQuery) => Promise<WorldList<TechniqueSummary>>;
  technique: (id: string) => Promise<TechniqueDetail | null>;
  sitemap: () => Promise<Response | null>;
}

/** The full view of an entry, as the pages use it (copied field by field by `guardEntryFull`). */
export interface EntryFullView extends EntryPreview {
  cwe: string[];
  advisories: EntryAdvisory[];
  signals: EntrySignal[];
  changes: EntryChange[];
}

export type { DeleteAccountResponse, Me, SavedSearch, SavedSearchListResponse, WatchItem, WatchListResponse };

/** The signed-in calls. Each sends `Authorization: Bearer` and nothing else about the visitor. */
export interface AccountClient {
  me: () => Promise<Me>;
  patchMe: (patch: MePatch) => Promise<Me>;
  watchList: () => Promise<WatchListResponse>;
  watch: (id: string, alertsOn?: boolean) => Promise<WatchItem>;
  unwatch: (id: string) => Promise<void>;
  savedList: () => Promise<SavedSearchListResponse>;
  saveSearch: (body: SavedSearchCreate) => Promise<SavedSearch>;
  deleteSearch: (id: string) => Promise<void>;
  deleteAccount: () => Promise<void>;
  /** The full entry, or null when it is missing or the API still answers `access: 'preview'`. */
  entryFull: (id: string) => Promise<EntryFullView | null>;
}
