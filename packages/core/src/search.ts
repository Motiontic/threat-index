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

export const MIN_PREFIX = 2;
export const MAX_PREFIX = 64;

/**
 * The first `depth` characters of the term, lowercase, anything outside [a-z0-9] replaced by `_`, padded
 * with `-` when the term is shorter. A busy prefix is split by asking for one more character.
 */
export function shardPrefixAt(term: string, depth: number): string {
  return term
    .toLowerCase()
    .slice(0, depth)
    .replace(/[^a-z0-9]/g, '_')
    .padEnd(depth, '-');
}

/** Two-character prefix: where every term starts before any split. */
export function shardPrefix(term: string): string {
  return shardPrefixAt(term, MIN_PREFIX);
}

/**
 * The shard prefix of `term`: start at two characters and go one deeper while the manifest says the
 * prefix was split. Bounded by MAX_PREFIX.
 */
export function resolvePrefix(term: string, splits: ReadonlySet<string>): string {
  let depth = MIN_PREFIX;
  let prefix = shardPrefixAt(term, depth);
  while (splits.has(prefix) && depth < MAX_PREFIX) prefix = shardPrefixAt(term, ++depth);
  return prefix;
}

/** lookup/search/v2/<prefix>.json (the v1 layout, lookup/search/<prefix>.json, is never read) */
export function searchShardKey(prefix: string): string {
  return `lookup/search/v2/${prefix}.json`;
}

/** lookup/search/v2/manifest.json: written after every shard, so its presence means the index is whole. */
export function searchManifestKey(): string {
  return 'lookup/search/v2/manifest.json';
}

export interface SearchManifest {
  builtAt: string; // ISO
  splits: string[]; // prefixes whose terms live in shards one character deeper
}

export interface SearchShard {
  builtAt: string; // ISO; the API's live delta covers rows modified after this
  terms: Record<string, string[]>; // term → entry keys (never empty)
  docs: Record<string, SearchHit>; // entry key → hit shown in results
  truncated?: string[]; // terms whose list kept only the MAX_POSTINGS most recently modified entries
}
