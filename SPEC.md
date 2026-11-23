# seams-m1: shared shapes for the public API, the web pages and the search index

## Why

Six features are built next, at the same time: the public API routes, the public web pages, the nightly
search index, the heavy E2B jobs, and two parser sets. The web pages read the API, and the API's search
reads the index the E2B job writes. Built in parallel, each pair must agree on shapes before either exists.
This change puts those shapes on `main` as types and pure helpers, so each feature builds against them.

It adds no product behaviour.

## What to build

### 1. API response types: `packages/core/src/api.ts`

Types only, plus one pure helper. Field names are camelCase in JSON.

```ts
import type { DisplayMode } from './licence';

export interface Credit { sourceId: string; name: string; text: string; url?: string }

/** What a visitor may see. Everything else needs a free account. */
export interface EntryPreview {
  key: string;            // CVE ID, or the source ID when there is no CVE
  kind: string;           // vulns.kind
  title: string;
  summary: string;
  aliases: string[];
  published?: string;
  modified?: string;
  cvss?: number;
  cvssVersion?: string;
  exploited: boolean;     // in KEV or another exploited-in-the-wild signal
  kevAdded?: string;
  epss?: number;
  credits: Credit[];
}

export interface EntryAdvisory {
  source: string; sourceId: string; status: string; url?: string;
  published?: string; modified?: string; display: DisplayMode;
  affected?: { ecosystem: string; name: string; introduced?: string; fixed?: string; range?: string }[];
}
export interface EntrySignal { kind: string; source: string; ref: string; firstSeen: string; url?: string }
export interface EntryChange { kind: string; old?: string; new?: string; at: string; source?: string }

export interface EntryFull extends EntryPreview {
  cwe: string[];
  advisories: EntryAdvisory[];
  signals: EntrySignal[];
  changes: EntryChange[];
}

export type EntryResponse =
  | { access: 'preview'; entry: EntryPreview }
  | { access: 'full'; entry: EntryFull };

export interface SearchHit {
  key: string; title: string; summary: string; cvss?: number; exploited: boolean; published?: string;
}
export interface SearchResponse { query: string; hits: SearchHit[]; total: number; cursor?: string; credits: Credit[] }

export interface IndexLetterResponse { letter: string; items: { key: string; title: string }[]; cursor?: string }

export interface SourceStatus {
  id: string; name: string; gives: string; pattern: string; cadence: string;
  licence: 'on' | 'ask' | 'wait' | 'link'; display: DisplayMode; credit: string;
  lastSuccess?: string; lastRunStatus?: string;
}
export interface SourcesResponse { sources: SourceStatus[] }

export interface ApiError { error: string }
```

### 2. Search index format: `packages/core/src/search.ts` (implemented, tested)

- `searchTerms(text: string): string[]`: lowercases, splits on anything that is not a letter, digit, `-`,
  `.` or `_`, drops terms shorter than 2 characters, keeps unique terms in order. Vulnerability IDs
  (`CVE-2025-3248`, `GHSA-xxxx-xxxx-xxxx`) stay whole.
- `shardPrefix(term: string): string`: the first two characters of the term, lowercase, with any character
  outside `[a-z0-9]` replaced by `_`.
- `searchShardKey(prefix)` → `lookup/search/<prefix>.json`.
- A shard file is `SearchShard`:

```ts
export interface SearchShard {
  builtAt: string;                         // ISO; the API's live delta covers rows modified after this
  terms: Record<string, string[]>;         // term → entry keys
  docs: Record<string, SearchHit>;         // entry key → hit shown in results
}
```

Tests: the ID cases, punctuation, unicode letters, repeats, and `shardPrefix` for short and odd terms.

### 3. More R2 keys in `packages/core/src/r2-keys.ts`

- `indexLetterKey(letter)` → `lookup/index/<letter>.json` where letter is `a`–`z` or `0` for digits,
  holding an `IndexLetterResponse`;
- `lakeKey(table, sourceId, year, part)` → `lake/<table>/<source>/<year>/part-<part>.parquet`;
- `sitemapKey()` → `sitemap.xml`.

## Not in scope

Any route, page, job or parser logic. Migrations, Wrangler configs, CI, dependencies.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. `@ti/core/api` and `@ti/core/search` exist with the names above; `search.ts` and the new key helpers
   have tests.
3. No other package changes.
