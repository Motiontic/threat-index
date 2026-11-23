/** Response and request types for the signed-in `/v1/me*` routes. JSON is camelCase. */

/** Most items one user can watch. */
export const MAX_WATCH_ITEMS = 1000;
/** Most saved searches one user can keep. */
export const MAX_SAVED_SEARCHES = 50;
/** Longest display name, in characters. */
export const MAX_DISPLAY_NAME_CHARS = 80;
/** Longest saved-search name, in characters. */
export const MAX_SAVED_SEARCH_NAME_CHARS = 80;

/** How often the digest email goes out. */
export type DigestCadence = 'daily' | 'weekly' | 'off';
/** Alert settings: instant alerts and a digest cadence are independent. */
export interface AlertSettings {
  instant: boolean;
  digest: DigestCadence;
  digestWeekday: number; // 0 = Sunday, UTC
}
/** The signed-in user's profile, from `GET /v1/me`. */
export interface Me {
  userId: string;
  email: string;
  displayName: string | null;
  alerts: AlertSettings;
}
/** Body of `PATCH /v1/me`: only the given fields change. */
export interface MePatch {
  displayName?: string | null;
  alerts?: Partial<AlertSettings>;
}

/** One watched entry, with its title. */
export interface WatchItem {
  entryKey: string;
  title: string;
  alertsOn: boolean;
  createdAt: string;
}
/** Response of `GET /v1/me/watch`. */
export interface WatchListResponse {
  items: WatchItem[];
  limit: number;
}

/** The filters of GET /v1/search, by its query-parameter names. */
export interface SavedSearchParams {
  type?: string[];
  sig?: string[];
  sev?: string[];
  year?: string[];
  sort?: 'rel' | 'new';
}
/** One saved search. */
export interface SavedSearch {
  id: string;
  name: string;
  query: string;
  params: SavedSearchParams;
  alertsOn: boolean;
  createdAt: string;
}
/** Body of `POST /v1/me/saved-searches`. */
export interface SavedSearchCreate {
  name: string;
  query: string;
  params?: SavedSearchParams;
  alertsOn?: boolean;
}
/** Response of `GET /v1/me/saved-searches`. */
export interface SavedSearchListResponse {
  items: SavedSearch[];
  limit: number;
}

/** Response of `DELETE /v1/me`. */
export interface DeleteAccountResponse {
  deleted: true;
}
