import { appendFileSync } from 'node:fs';
import { resolvePrefix } from '@ti/core/search';
import { describe, expect, it } from 'vitest';
import {
  buildIndex,
  LETTER_PAGE_ITEMS,
  MAX_POSTINGS,
  MAX_SHARD_BYTES,
  type VulnRow,
} from './search-index.ts';

const ENTRIES = 250_000;
const BUILT = '2026-11-24T00:00:00.000Z';
const enc = new TextEncoder();

// A deterministic LCG, so the skew is the same on every run.
let seed = 12345;
const rnd = () => {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed / 2 ** 32;
};

function synthetic(): VulnRow[] {
  const rows: VulnRow[] = [];
  const letters = 'abcdefghijklmnopqrstuvwxyz';
  for (let i = 0; i < ENTRIES; i++) {
    const words: string[] = [];
    if (rnd() < 0.6) words.push('apache'); // a few terms in more than half the titles
    if (rnd() < 0.55) words.push('vulnerability');
    if (rnd() < 0.52) words.push('log4j');
    if (rnd() < 0.5) words.push(`ap${Math.floor(rnd() * 40_000).toString(36)}`); // many terms sharing `ap`
    if (rnd() < 0.5) words.push(`la${Math.floor(rnd() * 40_000).toString(36)}`);
    if (rnd() < 0.4) words.push(`lo${Math.floor(rnd() * 40_000).toString(36)}`);
    words.push(`prod${Math.floor(rnd() * 5000)}`);
    words.push(`${letters[i % 26]}item`);
    rows.push({
      key: `CVE-2026-${String(i).padStart(6, '0')}`,
      kind: 'cve',
      title: `${words.join(' ')} flaw ${i}`,
      summary: '',
      modified: new Date(Date.UTC(2026, 0, 1) + i * 60_000).toISOString(),
      hot: 1,
      published: '2026-01-01',
    });
  }
  return rows;
}

describe('buildIndex at 250,000 entries with a skewed vocabulary', () => {
  it('writes no shard over the cap, no empty list, and letter pages of at most 500', () => {
    const rows = synthetic();
    const b = buildIndex(rows, [], BUILT);
    expect(b.stats.indexed).toBe(ENTRIES);

    const splits = new Set(b.manifest.splits);
    let largestShard = 0;
    let terms = 0;
    for (const [prefix, shard] of b.shards) {
      const size = enc.encode(JSON.stringify(shard)).length;
      largestShard = Math.max(largestShard, size);
      expect(size).toBeLessThanOrEqual(MAX_SHARD_BYTES);
      for (const [term, list] of Object.entries(shard.terms)) {
        terms++;
        expect(list.length).toBeGreaterThan(0);
        expect(list.length).toBeLessThanOrEqual(MAX_POSTINGS);
        expect(resolvePrefix(term, splits)).toBe(prefix);
      }
    }
    // The common terms are truncated, not dropped.
    for (const t of ['apache', 'vulnerability', 'log4j', 'cve']) {
      const shard = b.shards.get(resolvePrefix(t, splits));
      expect(shard?.terms[t]).toHaveLength(MAX_POSTINGS);
      expect(shard?.truncated).toContain(t);
    }
    expect(b.stats.splitPrefixes).toBeGreaterThan(0); // `ap`, `la` and `lo` did not fit as they were

    let largestPage = 0;
    let items = 0;
    for (const pages of b.letters.values()) {
      pages.forEach((page, i) => {
        largestPage = Math.max(largestPage, page.items.length);
        items += page.items.length;
        expect(page.items.length).toBeLessThanOrEqual(LETTER_PAGE_ITEMS);
        expect(page.cursor).toBe(i < pages.length - 1 ? `p${i + 1}` : undefined);
      });
    }
    expect(items).toBe(ENTRIES);

    const line = `synthetic ${ENTRIES} entries: shards=${b.shards.size} splits=${splits.size} terms=${terms} largestShardBytes=${largestShard} (cap ${MAX_SHARD_BYTES}) truncatedTerms=${b.stats.truncatedTerms} letterPages=${b.stats.letterPages} largestLetterPageItems=${largestPage}`;
    console.log(line);
    if (process.env.TI_PROOF_FILE) appendFileSync(process.env.TI_PROOF_FILE, `${line}\n`);
  }, 120_000);
});
