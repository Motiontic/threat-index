/**
 * Nightly search index (docs/IMPLEMENTATION_PLAN.md §8, "Search design"). Pages the hot set out of the API's
 * sandbox routes, builds an inverted index, and writes it to R2 as `lookup/search/v2/<prefix>.json` plus the A–Z
 * index pages and `sitemap.xml`. The API reads one shard per query term and adds a live delta from D1 for rows
 * modified after `builtAt`.
 */
import type { IndexLetterResponse, SearchHit } from '@ti/core/api';
import { inboxManifestKey } from '@ti/core/inbox';
import { indexLetterKey, sitemapKey } from '@ti/core/r2-keys';
import {
  MAX_PREFIX,
  MIN_PREFIX,
  type SearchManifest,
  type SearchShard,
  searchManifestKey,
  searchShardKey,
  searchTerms,
  shardPrefixAt,
} from '@ti/core/search';
import type { JobApi } from '../client.ts';
import type { Job, JobContext, JobDeps } from '../types.ts';

export const MAX_POSTINGS = 2000;
export const MAX_SHARD_BYTES = 3 * 1024 * 1024;
export const LETTER_PAGE_ITEMS = 500;
export const MAX_SITEMAP_ENTRIES = 49_000;
export const SUMMARY_CHARS = 160;
export const PAGE_LIMIT = 1000;
const UPLOAD_CONCURRENCY = 8;
const LETTERS = [...'abcdefghijklmnopqrstuvwxyz', '0'];

export type VulnRow = Record<string, unknown>;
export type AdvisoryRow = Record<string, unknown>;

export interface BuildStats {
  rows: number; // hot, well-formed rows seen
  skipped: number; // hot rows without a string key, title or modified
  indexed: number; // vulns that made it into the index
  shards: number;
  largestShardBytes: number;
  truncatedTerms: number; // terms over MAX_POSTINGS that kept only their most recent entries
  splitPrefixes: number; // prefixes that were too big and moved one character deeper
  letterPages: number;
  largestLetterPageItems: number;
}
export interface BuiltIndex {
  shards: Map<string, SearchShard>; // prefix → shard
  manifest: SearchManifest;
  letters: Map<string, IndexLetterResponse[]>; // 'a'..'z', '0' → pages (all 27 always have page 0)
  sitemap: string | null; // null when no site origin is set
  stats: BuildStats;
}

const byteLength = (text: string) => new TextEncoder().encode(text).length;
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function cweIds(raw: unknown): string[] {
  if (typeof raw !== 'string') return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function hitFor(row: VulnRow, key: string, title: string): SearchHit {
  const hit: SearchHit = {
    key,
    title,
    summary: (str(row.summary) ?? '').slice(0, SUMMARY_CHARS),
    exploited: row.kev_added != null && row.kev_added !== '',
  };
  if (typeof row.cvss === 'number') hit.cvss = row.cvss;
  const published = str(row.published);
  if (published) hit.published = published;
  return hit;
}

function xmlEscape(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function buildSitemap(origin: string, entries: { key: string; modified: string }[]): string {
  const urls: { loc: string; lastmod?: string }[] = [
    { loc: `${origin}/` },
    { loc: `${origin}/search` },
    { loc: `${origin}/sources` },
    ...LETTERS.map((l) => ({ loc: `${origin}/index/${l}` })),
  ];
  const recent = [...entries]
    .sort((a, b) => (a.modified < b.modified ? 1 : a.modified > b.modified ? -1 : a.key < b.key ? -1 : 1))
    .slice(0, MAX_SITEMAP_ENTRIES);
  for (const e of recent)
    urls.push({ loc: `${origin}/e/${encodeURIComponent(e.key)}`, lastmod: e.modified.slice(0, 10) });
  const body = urls
    .map(
      (u) =>
        `<url><loc>${xmlEscape(u.loc)}</loc>${u.lastmod ? `<lastmod>${xmlEscape(u.lastmod)}</lastmod>` : ''}</url>`,
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${body}\n</urlset>\n`;
}

/** Pure. No I/O, no clock: `builtAt` is passed in. */
export function buildIndex(
  vulns: VulnRow[],
  advisories: AdvisoryRow[],
  builtAt: string,
  opts: { siteOrigin?: string } = {},
): BuiltIndex {
  const stats: BuildStats = {
    rows: 0,
    skipped: 0,
    indexed: 0,
    shards: 0,
    largestShardBytes: 0,
    truncatedTerms: 0,
    splitPrefixes: 0,
    letterPages: 0,
    largestLetterPageItems: 0,
  };

  // vuln_key → [every advisory is rejected or withdrawn so far, has any]
  const dead = new Map<string, boolean>();
  for (const a of advisories) {
    const vk = str(a.vuln_key);
    if (!vk) continue;
    const gone = a.status === 'rejected' || a.status === 'withdrawn';
    dead.set(vk, (dead.get(vk) ?? true) && gone);
  }

  const postings = new Map<string, string[]>(); // term → entry keys (each row lists a term once)
  const docs = new Map<string, SearchHit>();
  const modifiedOf = new Map<string, string>();
  const letterItems = new Map<string, { key: string; title: string }[]>(LETTERS.map((l) => [l, []]));
  const sitemapEntries: { key: string; modified: string }[] = [];
  const seen = new Set<string>();

  for (const row of vulns) {
    if (Number(row.hot) !== 1) continue;
    const key = str(row.key);
    const title = str(row.title);
    const modified = str(row.modified);
    if (!key || title === undefined || !modified) {
      stats.skipped++;
      continue;
    }
    stats.rows++;
    if (seen.has(key)) continue; // primary key makes this impossible from D1; guard against a bad pager
    seen.add(key);
    if (dead.get(key) === true) continue;
    stats.indexed++;

    docs.set(key, hitFor(row, key, title));
    modifiedOf.set(key, modified);

    const terms = new Set<string>([
      ...searchTerms(title),
      ...searchTerms(str(row.summary) ?? ''),
      ...searchTerms(str(row.kind) ?? ''),
      ...cweIds(row.cwe).flatMap((c) => searchTerms(c)),
    ]);
    for (const term of terms) {
      const keys = postings.get(term);
      if (keys) keys.push(key);
      else postings.set(term, [key]);
    }

    const first = title.toLowerCase().charAt(0);
    letterItems.get(/^[a-z]$/.test(first) ? first : '0')?.push({ key, title });
    sitemapEntries.push({ key, modified });
  }

  // A term over MAX_POSTINGS keeps its most recently modified entries. Never an empty list.
  const truncated = new Set<string>();
  for (const [term, keys] of postings) {
    if (keys.length <= MAX_POSTINGS) continue;
    const mod = (k: string) => modifiedOf.get(k) as string;
    keys.sort((x, y) => (mod(x) < mod(y) ? 1 : mod(x) > mod(y) ? -1 : x < y ? -1 : x > y ? 1 : 0));
    postings.set(term, keys.slice(0, MAX_POSTINGS));
    truncated.add(term);
    stats.truncatedTerms++;
  }

  // Bytes each entry costs in a shard: its key inside a posting list, and its doc.
  const keyBytes = new Map<string, number>();
  const docBytes = new Map<string, number>();
  for (const [k, hit] of docs) {
    keyBytes.set(k, byteLength(k) + 3);
    docBytes.set(k, byteLength(k) + byteLength(JSON.stringify(hit)) + 4);
  }
  const assemble = (terms: string[]): SearchShard => {
    const shardTerms: Record<string, string[]> = {};
    const shardDocs: Record<string, SearchHit> = {};
    const trunc: string[] = [];
    for (const term of [...terms].sort()) {
      const list = [...(postings.get(term) as string[])].sort();
      shardTerms[term] = list;
      for (const k of list) shardDocs[k] = docs.get(k) as SearchHit;
      if (truncated.has(term)) trunc.push(term);
    }
    const shard: SearchShard = { builtAt, terms: shardTerms, docs: shardDocs };
    if (trunc.length > 0) shard.truncated = trunc;
    return shard;
  };
  const estimate = (terms: string[]): number => {
    let n = 80;
    const inShard = new Set<string>();
    for (const term of terms) {
      n += byteLength(term) + 6;
      for (const k of postings.get(term) as string[]) {
        n += keyBytes.get(k) as number;
        if (!inShard.has(k)) {
          inShard.add(k);
          n += docBytes.get(k) as number;
        }
      }
    }
    return n;
  };

  const shards = new Map<string, SearchShard>();
  const splits: string[] = [];
  // Put `terms` (all sharing `prefix` at `depth`) in one shard, or split them one character deeper.
  const place = (prefix: string, terms: string[], depth: number): void => {
    let shard: SearchShard | null = null;
    let size = 0;
    if (estimate(terms) <= MAX_SHARD_BYTES) {
      shard = assemble(terms);
      size = byteLength(JSON.stringify(shard));
      if (size > MAX_SHARD_BYTES) shard = null;
    }
    if (shard) {
      shards.set(prefix, shard);
      stats.largestShardBytes = Math.max(stats.largestShardBytes, size);
      return;
    }
    const groups = new Map<string, string[]>();
    for (const term of terms) {
      const p = shardPrefixAt(term, depth + 1);
      const g = groups.get(p);
      if (g) g.push(term);
      else groups.set(p, [term]);
    }
    if (depth + 1 > MAX_PREFIX || terms.length < 2)
      throw new Error(
        `search shard "${prefix}" is over ${MAX_SHARD_BYTES} bytes and cannot be split further`,
      );
    splits.push(prefix);
    for (const [p, g] of [...groups].sort(([x], [y]) => (x < y ? -1 : 1))) place(p, g, depth + 1);
  };
  const roots = new Map<string, string[]>();
  for (const term of postings.keys()) {
    const p = shardPrefixAt(term, MIN_PREFIX);
    const g = roots.get(p);
    if (g) g.push(term);
    else roots.set(p, [term]);
  }
  for (const [p, g] of [...roots].sort(([x], [y]) => (x < y ? -1 : 1))) place(p, g, MIN_PREFIX);
  stats.shards = shards.size;
  stats.splitPrefixes = splits.length;
  splits.sort();
  const manifest: SearchManifest = { builtAt, splits };

  const collate = new Intl.Collator(undefined, { sensitivity: 'base' });
  const letters = new Map<string, IndexLetterResponse[]>();
  for (const letter of LETTERS) {
    const items = (letterItems.get(letter) ?? []).sort(
      (a, b) => collate.compare(a.title, b.title) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0),
    );
    const pages: IndexLetterResponse[] = [];
    for (let i = 0; i === 0 || i < items.length; i += LETTER_PAGE_ITEMS) {
      const page: IndexLetterResponse = { letter, items: items.slice(i, i + LETTER_PAGE_ITEMS) };
      if (i + LETTER_PAGE_ITEMS < items.length) page.cursor = `p${pages.length + 1}`;
      pages.push(page);
      stats.largestLetterPageItems = Math.max(stats.largestLetterPageItems, page.items.length);
    }
    stats.letterPages += pages.length;
    letters.set(letter, pages);
  }

  const sitemap = opts.siteOrigin ? buildSitemap(opts.siteOrigin, sitemapEntries) : null;
  return { shards, manifest, letters, sitemap, stats };
}

async function pageAll(api: JobApi, table: 'vulns' | 'advisories'): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  let after: string | undefined;
  for (;;) {
    const page: { rows: Record<string, unknown>[]; next: string | null } = await api.rows(table, {
      ...(after ? { after } : {}),
      limit: PAGE_LIMIT,
    });
    for (const r of page.rows) out.push(r);
    if (page.next === null) return out;
    if (page.next === after) throw new Error(`rows/${table} paging did not advance`);
    after = page.next;
  }
}

function siteOrigin(log: JobContext['log']): string | undefined {
  const origin = process.env.SITE_ORIGIN;
  if (!origin) {
    log('sitemap skipped: SITE_ORIGIN is not set');
    return undefined;
  }
  if (!origin.startsWith('https://') || origin.endsWith('/')) {
    log('sitemap skipped: SITE_ORIGIN must start with https:// and have no trailing slash');
    return undefined;
  }
  return origin;
}

export async function run(job: Job, ctx: JobContext, _deps: JobDeps = {}): Promise<void> {
  const api = ctx.api;
  // Before paging: a row changed while we read is still newer than `builtAt`, so the API's delta covers it.
  const builtAt = new Date().toISOString();
  const vulns = await pageAll(api, 'vulns');
  const advisories = await pageAll(api, 'advisories');
  const built = buildIndex(vulns, advisories, builtAt, { siteOrigin: siteOrigin(ctx.log) });
  ctx.log('index built', { ...built.stats, advisories: advisories.length, builtAt });

  const files: { key: string; body: string; type: string }[] = [];
  for (const [prefix, shard] of built.shards)
    files.push({ key: searchShardKey(prefix), body: JSON.stringify(shard), type: 'application/json' });
  for (const [letter, pages] of built.letters)
    for (const [i, page] of pages.entries())
      files.push({ key: indexLetterKey(letter, i), body: JSON.stringify(page), type: 'application/json' });
  if (built.sitemap !== null) files.push({ key: sitemapKey(), body: built.sitemap, type: 'application/xml' });

  for (let i = 0; i < files.length; i += UPLOAD_CONCURRENCY)
    await Promise.all(
      files.slice(i, i + UPLOAD_CONCURRENCY).map((f) => api.putObject(f.key, f.body, f.type)),
    );
  // After every shard: the API treats a bucket without this file as having no index.
  const manifestBody = JSON.stringify(built.manifest);
  await api.putObject(searchManifestKey(), manifestBody, 'application/json');
  files.push({ key: searchManifestKey(), body: manifestBody, type: 'application/json' });

  // Old-layout shards (lookup/search/<prefix>.json) and letter files (lookup/index/<letter>.json), and any
  // object this build no longer writes, are deleted so nothing stale can be read.
  const written = new Set(files.map((f) => f.key));
  const stale: string[] = [];
  for (const prefix of ['lookup/search/', 'lookup/index/'])
    for await (const o of api.list(prefix)) if (!written.has(o.key)) stale.push(o.key);
  let deleted = 0;
  for (let i = 0; i < stale.length; i += UPLOAD_CONCURRENCY)
    await Promise.all(
      stale.slice(i, i + UPLOAD_CONCURRENCY).map(async (key) => {
        try {
          await api.deleteObject(key);
          deleted++;
        } catch (err) {
          ctx.log('stale index object not deleted', { key, error: String(err) });
        }
      }),
    );
  ctx.log('stale index objects deleted', { found: stale.length, deleted });

  // Last, so `complete` only sees a manifest once everything above is in place.
  await api.putObject(
    inboxManifestKey(job.id),
    JSON.stringify({ jobId: job.id, createdAt: new Date().toISOString(), chunks: [] }),
    'application/json',
  );
  ctx.log('index uploaded', { objects: files.length + 1 });
}
