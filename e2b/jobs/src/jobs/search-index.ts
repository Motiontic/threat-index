/**
 * Nightly search index (docs/IMPLEMENTATION_PLAN.md §8, "Search design"). Pages the hot set out of the API's
 * sandbox routes, builds an inverted index, and writes it to R2 as `lookup/search/<prefix>.json` plus the A–Z
 * index files and `sitemap.xml`. The API reads one shard per query term and adds a live delta from D1 for rows
 * modified after `builtAt`.
 */
import type { IndexLetterResponse, SearchHit } from '@ti/core/api';
import { inboxManifestKey } from '@ti/core/inbox';
import { indexLetterKey, sitemapKey } from '@ti/core/r2-keys';
import { type SearchShard, searchShardKey, searchTerms, shardPrefix } from '@ti/core/search';
import { SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';
import type { Job, JobContext } from '../types.ts';

export const MAX_POSTINGS = 2000;
export const MAX_SHARD_BYTES = 6 * 1024 * 1024;
export const MAX_LETTER_ITEMS = 20_000;
export const MAX_SITEMAP_ENTRIES = 49_000;
export const SUMMARY_CHARS = 160;
export const PAGE_LIMIT = 1000;
export const MAX_OBJECT_BYTES = 50 * 1024 * 1024;
const RETRIES = 3;
const UPLOAD_CONCURRENCY = 8;
const LETTERS = [...'abcdefghijklmnopqrstuvwxyz', '0'];

export type VulnRow = Record<string, unknown>;
export type AdvisoryRow = Record<string, unknown>;

export interface IndexIo {
  rows(
    table: 'vulns' | 'advisories',
    after: string | null,
    limit: number,
  ): Promise<{ rows: Record<string, unknown>[]; next: string | null }>;
  put(key: string, body: string, contentType: string): Promise<void>;
}

export interface BuildStats {
  rows: number; // hot, well-formed rows seen
  skipped: number; // hot rows without a string key, title or modified
  indexed: number; // vulns that made it into the index
  shards: number;
  largestShardBytes: number;
  trimmedTerms: number; // posting lists emptied, by either rule
}
export interface BuiltIndex {
  shards: Map<string, SearchShard>; // prefix → shard
  letters: Map<string, IndexLetterResponse>; // 'a'..'z', '0' → page (all 27 always present)
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
    trimmedTerms: 0,
  };

  // vuln_key → [every advisory is rejected or withdrawn so far, has any]
  const dead = new Map<string, boolean>();
  for (const a of advisories) {
    const vk = str(a.vuln_key);
    if (!vk) continue;
    const gone = a.status === 'rejected' || a.status === 'withdrawn';
    dead.set(vk, (dead.get(vk) ?? true) && gone);
  }

  const postings = new Map<string, Map<string, Set<string>>>(); // prefix → term → keys
  const docs = new Map<string, SearchHit>();
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

    const hit = hitFor(row, key, title);
    docs.set(key, hit);

    const terms = new Set<string>([
      ...searchTerms(title),
      ...searchTerms(str(row.summary) ?? ''),
      ...searchTerms(str(row.kind) ?? ''),
      ...cweIds(row.cwe).flatMap((c) => searchTerms(c)),
    ]);
    for (const term of terms) {
      const prefix = shardPrefix(term);
      const shardTerms = postings.get(prefix) ?? new Map<string, Set<string>>();
      postings.set(prefix, shardTerms);
      const keys = shardTerms.get(term) ?? new Set<string>();
      shardTerms.set(term, keys);
      keys.add(key);
    }

    const first = title.toLowerCase().charAt(0);
    letterItems.get(/^[a-z]$/.test(first) ? first : '0')?.push({ key, title });
    sitemapEntries.push({ key, modified });
  }

  const shards = new Map<string, SearchShard>();
  for (const [prefix, termMap] of [...postings].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const lists = new Map<string, string[]>();
    for (const [term, keys] of termMap) {
      if (keys.size > MAX_POSTINGS) {
        lists.set(term, []);
        stats.trimmedTerms++;
      } else lists.set(term, [...keys].sort());
    }
    const assemble = (): SearchShard => {
      const shardDocs: Record<string, SearchHit> = {};
      const terms: Record<string, string[]> = {};
      for (const term of [...lists.keys()].sort()) {
        const list = lists.get(term) as string[];
        terms[term] = list;
        for (const k of list) shardDocs[k] = docs.get(k) as SearchHit;
      }
      return { builtAt, terms, docs: shardDocs };
    };
    let shard = assemble();
    let size = byteLength(JSON.stringify(shard));
    if (size > MAX_SHARD_BYTES) {
      // Largest lists first. `estimate` only counts the posting bytes saved (an upper bound on the shard
      // size), so a verify pass runs once it says we fit, and the loop carries on if the real size disagrees.
      const order = [...lists].filter(([, l]) => l.length > 0).sort((a, b) => b[1].length - a[1].length);
      let estimate = size;
      for (const [term, list] of order) {
        if (estimate <= MAX_SHARD_BYTES) {
          shard = assemble();
          size = byteLength(JSON.stringify(shard));
          estimate = size;
          if (size <= MAX_SHARD_BYTES) break;
        }
        estimate -= list.reduce((n, k) => n + byteLength(k) + 3, 0);
        lists.set(term, []);
        stats.trimmedTerms++;
      }
      shard = assemble();
      size = byteLength(JSON.stringify(shard));
    }
    shards.set(prefix, shard);
    stats.largestShardBytes = Math.max(stats.largestShardBytes, size);
  }
  stats.shards = shards.size;

  const collate = new Intl.Collator(undefined, { sensitivity: 'base' });
  const letters = new Map<string, IndexLetterResponse>();
  for (const letter of LETTERS) {
    const items = (letterItems.get(letter) ?? [])
      .sort((a, b) => collate.compare(a.title, b.title) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      .slice(0, MAX_LETTER_ITEMS);
    letters.set(letter, { letter, items });
  }

  const sitemap = opts.siteOrigin ? buildSitemap(opts.siteOrigin, sitemapEntries) : null;
  return { shards, letters, sitemap, stats };
}

/** A minimal signed client for the sandbox `rows` and `objects` routes, with `client.ts`'s retry rule. */
export function jobIo(
  job: Job,
  deps: { fetch?: typeof fetch; now?: () => number; sleep?: (ms: number) => Promise<void> } = {},
): IndexIo {
  const doFetch = deps.fetch ?? fetch;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  async function call(
    method: 'GET' | 'PUT',
    path: string,
    query: string,
    body: string,
    contentType: string | undefined,
    what: string,
  ): Promise<Response> {
    let lastError = '';
    for (let attempt = 0; attempt <= RETRIES; attempt++) {
      if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
      const ts = Math.floor(now() / 1000);
      const headers: Record<string, string> = {
        [TIMESTAMP_HEADER]: String(ts),
        [SIGNATURE_HEADER]: await signRequest(job.hmac, method, path, ts, body),
      };
      if (contentType) headers['content-type'] = contentType;
      let res: Response;
      try {
        res = await doFetch(`${job.apiBase}${path}${query}`, {
          method,
          headers,
          ...(method === 'PUT' ? { body } : {}),
        });
      } catch {
        lastError = 'network error';
        continue;
      }
      if (res.ok) return res;
      if (res.status >= 500) {
        lastError = `status ${res.status}`;
        continue;
      }
      throw new Error(`${what} refused: status ${res.status}`);
    }
    throw new Error(`${what} failed after retries: ${lastError}`);
  }

  return {
    async rows(table, after, limit) {
      const path = `/internal/jobs/${job.id}/rows/${table}`;
      const q = new URLSearchParams();
      if (after !== null) q.set('after', after);
      q.set('limit', String(limit));
      const res = await call('GET', path, `?${q}`, '', undefined, `rows/${table}`);
      const data = (await res.json()) as { rows?: unknown; next?: unknown };
      if (!Array.isArray(data.rows) || !(data.next === null || typeof data.next === 'string'))
        throw new Error(`rows/${table} reply has the wrong shape`);
      return { rows: data.rows as Record<string, unknown>[], next: data.next };
    },
    async put(key, body, contentType) {
      if (byteLength(body) > MAX_OBJECT_BYTES)
        throw new Error(`object ${key} is over ${MAX_OBJECT_BYTES} bytes`);
      const path = `/internal/jobs/${job.id}/objects/${key.split('/').map(encodeURIComponent).join('/')}`;
      await call('PUT', path, '', body, contentType, `put ${key}`);
    },
  };
}

async function pageAll(io: IndexIo, table: 'vulns' | 'advisories'): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  let after: string | null = null;
  for (;;) {
    const page: { rows: Record<string, unknown>[]; next: string | null } = await io.rows(
      table,
      after,
      PAGE_LIMIT,
    );
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

export async function run(job: Job, ctx: JobContext, io: IndexIo = jobIo(job)): Promise<void> {
  // Before paging: a row changed while we read is still newer than `builtAt`, so the API's delta covers it.
  const builtAt = new Date().toISOString();
  const vulns = await pageAll(io, 'vulns');
  const advisories = await pageAll(io, 'advisories');
  const built = buildIndex(vulns, advisories, builtAt, { siteOrigin: siteOrigin(ctx.log) });
  ctx.log('index built', { ...built.stats, advisories: advisories.length, builtAt });

  const files: { key: string; body: string; type: string }[] = [];
  for (const [prefix, shard] of built.shards)
    files.push({ key: searchShardKey(prefix), body: JSON.stringify(shard), type: 'application/json' });
  for (const [letter, page] of built.letters)
    files.push({ key: indexLetterKey(letter), body: JSON.stringify(page), type: 'application/json' });
  if (built.sitemap !== null) files.push({ key: sitemapKey(), body: built.sitemap, type: 'application/xml' });

  for (let i = 0; i < files.length; i += UPLOAD_CONCURRENCY)
    await Promise.all(files.slice(i, i + UPLOAD_CONCURRENCY).map((f) => io.put(f.key, f.body, f.type)));

  // Last, so `complete` only sees a manifest once everything above is in place.
  await io.put(
    inboxManifestKey(job.id),
    JSON.stringify({ jobId: job.id, createdAt: new Date().toISOString(), chunks: [] }),
    'application/json',
  );
  ctx.log('index uploaded', { objects: files.length + 1 });
}
