# 0004. Search from nightly R2 shards, not D1 full-text search

- Status: accepted
- Date: 2026-11-22 (layout revised 2026-11-24, see Revision)

## Context

D1 supports SQLite FTS5, but each indexed document writes several rows to FTS shadow tables. Indexing about 1M hot rows would use most of the free 100,000-writes-a-day budget for weeks.

## Decision

- **Nightly shards:** an E2B job builds an inverted index of the hot set (IDs, aliases, titles, packages, tags) as small JSON shards, `lookup/search/<prefix>.json`, in R2.
- **One shard per term:** the API reads one shard per query term and intersects the results.
- **Live delta:** items changed since the last build are matched with `LIKE` over recently modified D1 rows.
- **Exact IDs** (any alias) resolve through the `advisories` primary key.

## Consequences

- Search costs no D1 writes and a few R2 reads per query.
- New items are searchable straight away through the delta.
- Cloudflare AI Search could replace this later.

## Revision: layout and limits at scale (2026-11-24)

The first layout (`lookup/search/<2-char prefix>.json`, one 6 MiB cap, empty list for a term over 2,000 entries,
one `lookup/index/<letter>.json` of up to 20,000 items) broke at about 211,000 hot entries: busy prefixes went over
the cap and were emptied, `apache` and `log4j` matched nothing, and `/index/a` was 2.5 MB.

- **Shards:** `lookup/search/v2/<prefix>.json`. A prefix starts at two characters (`~` pads shorter terms). If its
  shard would pass `MAX_SHARD_BYTES` (3 MiB) the writer splits it one character deeper, repeatedly, and lists the
  split prefixes in `lookup/search/v2/manifest.json` (`{ builtAt, splits }`). The API reads the manifest, then
  resolves each term by going one character deeper while its prefix is in `splits`: one manifest read plus one
  shard read per distinct prefix. The manifest is written after every shard.
- **Never empty:** a term over `MAX_POSTINGS` (2,000) keeps its 2,000 most recently modified entries and is named in
  the shard's `truncated`. The API treats it as a normal list. If a shard still cannot fit (a single term, or the
  64-character depth limit) the job fails and writes no manifest.
- **A–Z index:** `lookup/index/<letter>/<n>.json`, pages of at most 500 items. A page's `cursor` is `p<n+1>`;
  `GET /v1/index/:letter` serves page 0, or `?cursor=p<n>`, and falls back to D1 (key cursor) when page 0 is absent.
  A missing later page is `400 bad_cursor`.
- **Old layout:** the API never reads `lookup/search/<prefix>.json` or `lookup/index/<letter>.json`. A bucket with no
  manifest is queried live in D1. After a successful build the job lists `lookup/search/` and `lookup/index/` and
  deletes every object it did not just write.
- **Limits:** truncation means a common term finds only its 2,000 most recent entries (plus the live delta);
  queries that combine terms are intersected from those lists. Sized for 500,000 hot entries.
