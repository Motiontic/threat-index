import type { SearchHit } from './api';

/** Search index format shared by the nightly E2B job (writer) and the API (reader). */

/**
 * Lowercase, split on anything that is not a letter, digit, `-`, `.` or `_`, drop terms under 2
 * characters, keep unique terms in order. Vulnerability IDs stay whole.
 */
export function searchTerms(text: string): string[] {
  const seen = new Set<string>();
  for (const t of text.toLowerCase().split(/[^\p{L}\p{N}\-._]+/u)) {
    if (t.length >= 2) seen.add(t);
  }
  return [...seen];
}

/** First two characters of the term, lowercase, anything outside [a-z0-9] replaced by `_`. */
export function shardPrefix(term: string): string {
  return term
    .toLowerCase()
    .slice(0, 2)
    .replace(/[^a-z0-9]/g, '_');
}

/** lookup/search/<prefix>.json */
export function searchShardKey(prefix: string): string {
  return `lookup/search/${prefix}.json`;
}

export interface SearchShard {
  builtAt: string; // ISO; the API's live delta covers rows modified after this
  terms: Record<string, string[]>; // term → entry keys
  docs: Record<string, SearchHit>; // entry key → hit shown in results
}
