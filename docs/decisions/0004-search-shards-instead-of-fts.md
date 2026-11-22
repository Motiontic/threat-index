# 0004. Search from nightly R2 shards, not D1 full-text search

- Status: accepted
- Date: 2026-11-22

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
