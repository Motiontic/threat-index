import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolvePrefix } from '@ti/core/search';
import { describe, expect, it } from 'vitest';
import { synthetic } from './search-index.synth.ts';
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

describe('buildIndex at 250,000 entries with a skewed vocabulary', () => {
  it('writes no shard over the cap, no empty list, and letter pages of at most 500', () => {
    const rows = synthetic(ENTRIES);
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

const jobsDir = fileURLToPath(new URL('../..', import.meta.url));

describe('the whole search-index job with the Node heap capped at 1,536 MB', () => {
  it('finishes on 250,000 entries: bounded heap, objects written one at a time', () => {
    execFileSync(
      process.execPath,
      ['build.mjs', 'src/jobs/search-index.heap-run.ts', 'dist/search-index.heap-run.mjs'],
      {
        cwd: jobsDir,
        stdio: 'pipe',
      },
    );
    const out = execFileSync(
      process.execPath,
      ['--max-old-space-size=1536', 'dist/search-index.heap-run.mjs', String(ENTRIES)],
      { cwd: jobsDir, encoding: 'utf8', maxBuffer: 1 << 20 },
    );
    const r = JSON.parse(out) as {
      peakHeapMB: number;
      heapLimitMB: number;
      objects: number;
      totalBytes: number;
    };
    expect(r.heapLimitMB).toBeLessThanOrEqual(1600); // the cap really applied to the child
    expect(r.peakHeapMB).toBeLessThan(1200);
    expect(r.objects).toBeGreaterThan(100);
    expect(r.totalBytes).toBeLessThan(1024 ** 3); // the layout decision in SPEC.md §2
    const line = `job at the 1536 MB cap, ${ENTRIES} entries: ${out.trim().replace(/,"log":.*$/, '}')}`;
    console.log(line);
    if (process.env.TI_PROOF_FILE) appendFileSync(process.env.TI_PROOF_FILE, `${line}\n`);
  }, 300_000);
});
