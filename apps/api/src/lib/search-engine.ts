import type { SearchHit } from '@ti/core/api';
import { normaliseId } from '@ti/core/ids';
import { type SearchShard, searchShardKey, searchTerms, shardPrefix } from '@ti/core/search';
import { SOURCES } from '@ti/sources/registry';
import { parseSources } from './search-credits';
import type { SearchParams, Severity } from './search-params';

/**
 * Search over the R2 shards (written nightly by the `search-index` job), a live delta from D1 for rows
 * changed since the build, and an exact-ID path that skips the index. See docs/IMPLEMENTATION_PLAN.md §8.
 */

export const MAX_SHARD_OBJECT_BYTES = 16 * 1024 * 1024;
export const MAX_CANDIDATES = 5000;
export const DELTA_LIMIT = 500;
export const NO_INDEX_LIMIT = 1000;

export interface SearchEnv {
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  BUCKET: R2Bucket;
}
export interface SearchResult {
  hits: SearchHit[];
  total: number;
  sources: string[][]; // `vulns.sources` of each hit on the page, for credits
}
type Row = Record<string, unknown>;
interface Found {
  hit: SearchHit;
  sources: string[];
}

const COLS = 'key, title, summary, cvss, kev_added, published, sources';
const ID_RE = /^[A-Za-z][A-Za-z0-9]*[-:_][A-Za-z0-9._:-]+$/;
const SEV_SQL: Record<Severity, string> = {
  critical: 'cvss >= 9.0',
  high: '(cvss >= 7.0 AND cvss < 9.0)',
  medium: '(cvss >= 4.0 AND cvss < 7.0)',
  low: '(cvss > 0 AND cvss < 4.0)',
};
const SEV_RANGE: Record<Severity, (c: number) => boolean> = {
  critical: (c) => c >= 9,
  high: (c) => c >= 7 && c < 9,
  medium: (c) => c >= 4 && c < 7,
  low: (c) => c > 0 && c < 4,
};

function rowToHit(row: Row): Found | null {
  if (typeof row.key !== 'string' || typeof row.title !== 'string') return null;
  const hit: SearchHit = {
    key: row.key,
    title: row.title,
    summary: typeof row.summary === 'string' ? row.summary.slice(0, 160) : '',
    exploited: row.kev_added != null && row.kev_added !== '',
  };
  if (typeof row.cvss === 'number') hit.cvss = row.cvss;
  if (typeof row.published === 'string' && row.published) hit.published = row.published;
  return { hit, sources: parseSources(row.sources) };
}

/** Filters in code. Repeated values of one filter are OR'd; different filters are AND'd. */
function passes(h: SearchHit, p: SearchParams): boolean {
  if (p.types.length > 0) {
    const mal = h.key.startsWith('MAL-');
    if (!(mal ? p.types.includes('mal') : p.types.includes('vuln'))) return false;
  }
  if (p.kev && !h.exploited) return false;
  if (p.sevs.length > 0 && !(h.cvss !== undefined && p.sevs.some((s) => SEV_RANGE[s](h.cvss as number))))
    return false;
  if (p.years.length > 0 && !(h.published && p.years.includes(h.published.slice(0, 4)))) return false;
  return true;
}

/** The same filters as SQL, as `AND`-able clauses with positional binds. */
function filterSql(p: SearchParams): { clauses: string[]; binds: unknown[] } {
  const clauses: string[] = ['hot = 1'];
  const binds: unknown[] = [];
  if (p.types.length > 0) {
    const parts: string[] = [];
    if (p.types.includes('vuln')) parts.push("substr(key, 1, 4) != 'MAL-'");
    if (p.types.includes('mal')) parts.push("substr(key, 1, 4) = 'MAL-'");
    clauses.push(parts.length > 0 ? `(${parts.join(' OR ')})` : '0');
  }
  if (p.kev) clauses.push("(kev_added IS NOT NULL AND kev_added != '')");
  if (p.sevs.length > 0) clauses.push(`(${p.sevs.map((s) => SEV_SQL[s]).join(' OR ')})`);
  if (p.years.length > 0) {
    clauses.push(`substr(published, 1, 4) IN (${p.years.map(() => '?').join(', ')})`);
    binds.push(...p.years);
  }
  return { clauses, binds };
}

function sortHits(found: Found[], p: SearchParams): void {
  const num = (v: number | undefined) => v ?? Number.NEGATIVE_INFINITY;
  const pub = (a: SearchHit, b: SearchHit) =>
    a.published === b.published
      ? 0
      : !a.published
        ? 1
        : !b.published
          ? -1
          : a.published < b.published
            ? 1
            : -1;
  const byKey = (a: SearchHit, b: SearchHit) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  if (p.sort === 'new' || p.terms.length === 0) {
    found.sort((x, y) => pub(x.hit, y.hit) || byKey(x.hit, y.hit));
    return;
  }
  const score = new Map<string, number>();
  for (const f of found) {
    const t = new Set(searchTerms(f.hit.title));
    score.set(f.hit.key, p.terms.filter((q) => t.has(q)).length);
  }
  found.sort(
    (x, y) =>
      (score.get(y.hit.key) ?? 0) - (score.get(x.hit.key) ?? 0) ||
      Number(y.hit.exploited) - Number(x.hit.exploited) ||
      num(y.hit.cvss) - num(x.hit.cvss) ||
      pub(x.hit, y.hit) ||
      byKey(x.hit, y.hit),
  );
}

function escapeLike(term: string): string {
  return term.replace(/[\\%_]/g, (c) => `\\${c}`);
}

function validShard(data: unknown, terms: string[]): SearchShard | null {
  if (!data || typeof data !== 'object') return null;
  const s = data as Record<string, unknown>;
  if (typeof s.builtAt !== 'string' || Number.isNaN(Date.parse(s.builtAt))) return null;
  if (!s.terms || typeof s.terms !== 'object' || Array.isArray(s.terms)) return null;
  if (!s.docs || typeof s.docs !== 'object' || Array.isArray(s.docs)) return null;
  const t = s.terms as Record<string, unknown>;
  for (const term of terms) {
    const list = Object.hasOwn(t, term) ? t[term] : undefined;
    if (list !== undefined && !(Array.isArray(list) && list.every((k) => typeof k === 'string'))) return null;
  }
  return s as unknown as SearchShard;
}

async function readShards(env: SearchEnv, terms: string[]): Promise<Map<string, SearchShard | null>> {
  const byPrefix = new Map<string, string[]>();
  for (const t of terms) byPrefix.set(shardPrefix(t), [...(byPrefix.get(shardPrefix(t)) ?? []), t]);
  const out = new Map<string, SearchShard | null>();
  await Promise.all(
    [...byPrefix].map(async ([prefix, ts]) => {
      const key = searchShardKey(prefix);
      const obj = await env.BUCKET.get(key); // an R2 failure propagates: 503
      if (!obj) return void out.set(prefix, null);
      if (obj.size > MAX_SHARD_OBJECT_BYTES) {
        console.error(JSON.stringify({ level: 'warn', msg: 'search shard too large', key, size: obj.size }));
        return void out.set(prefix, null);
      }
      let shard: SearchShard | null = null;
      try {
        shard = validShard(await obj.json(), ts);
      } catch {
        shard = null;
      }
      if (!shard)
        console.error(JSON.stringify({ level: 'warn', msg: 'search shard failed shape check', key }));
      out.set(prefix, shard);
    }),
  );
  return out;
}

async function liveQuery(
  env: SearchEnv,
  p: SearchParams,
  terms: string[],
  after: string | null,
  limit: number,
): Promise<Found[]> {
  const { clauses, binds } = filterSql(p);
  if (after !== null) {
    clauses.push('modified > ?');
    binds.push(after);
  }
  const all: unknown[] = [];
  const where = [...clauses];
  // Filter binds come first in `binds`; keep positional order: year binds precede modified and term binds.
  for (const t of terms) {
    where.push("lower(key || ' ' || title || ' ' || COALESCE(summary, '')) LIKE ? ESCAPE '\\'");
    all.push(`%${escapeLike(t)}%`);
  }
  const rows = await env.DB_VULNS.prepare(
    `SELECT ${COLS} FROM vulns WHERE ${where.join(' AND ')} ORDER BY modified DESC LIMIT ${limit}`,
  )
    .bind(...binds, ...all)
    .all<Row>();
  const out: Found[] = [];
  for (const row of rows.results) {
    const f = rowToHit(row);
    if (!f) continue;
    // `LIKE` is a substring match; confirm whole terms so `log` does not match `login`.
    const have = new Set(searchTerms(`${f.hit.key} ${f.hit.title} ${String(row.summary ?? '')}`));
    if (terms.every((t) => have.has(t))) out.push(f);
  }
  return out;
}

async function exactId(env: SearchEnv, p: SearchParams): Promise<Found | null> {
  const id = normaliseId(p.q);
  const read = async (key: string) => {
    const row = await env.DB_VULNS.prepare(`SELECT ${COLS} FROM vulns WHERE key = ?1 AND hot = 1`)
      .bind(key)
      .first<Row>();
    return row ? rowToHit(row) : null;
  };
  let found = await read(id);
  if (!found) {
    const ids = SOURCES.map((s) => s.id);
    const row = await env.DB_ADVISORIES.prepare(
      `SELECT vuln_key FROM advisories WHERE source IN (${ids.map(() => '?').join(', ')}) AND source_id IN (?, ?) AND vuln_key IS NOT NULL LIMIT 1`,
    )
      .bind(...ids, p.q, id)
      .first<{ vuln_key: string }>();
    if (row?.vuln_key) found = await read(row.vuln_key);
  }
  return found && passes(found.hit, p) ? found : null;
}

function isExactIdQuery(p: SearchParams): boolean {
  return (
    p.terms.length === 1 &&
    searchTerms(p.q).length === 1 &&
    /\d/.test(p.q) &&
    p.q.length >= 4 &&
    p.q.length <= 80 &&
    ID_RE.test(p.q)
  );
}

async function browse(env: SearchEnv, p: SearchParams): Promise<SearchResult> {
  const { clauses, binds } = filterSql(p);
  const where = clauses.join(' AND ');
  const total = await env.DB_VULNS.prepare(`SELECT COUNT(*) AS n FROM vulns WHERE ${where}`)
    .bind(...binds)
    .first<{ n: number }>();
  const rows = await env.DB_VULNS.prepare(
    `SELECT ${COLS} FROM vulns WHERE ${where} ORDER BY published IS NULL, published DESC, key LIMIT ? OFFSET ?`,
  )
    .bind(...binds, p.limit, p.offset)
    .all<Row>();
  const found = rows.results.map(rowToHit).filter((f): f is Found => f !== null);
  return { hits: found.map((f) => f.hit), total: total?.n ?? 0, sources: found.map((f) => f.sources) };
}

export async function search(env: SearchEnv, p: SearchParams): Promise<SearchResult> {
  if (p.q === '') return browse(env, p);
  if (p.terms.length === 0) return { hits: [], total: 0, sources: [] };

  if (isExactIdQuery(p)) {
    const hit = await exactId(env, p);
    if (hit) return { hits: [hit.hit], total: 1, sources: [hit.sources] };
  }

  const shards = await readShards(env, p.terms);
  const candidates = new Map<string, Found>();
  const present = [...shards.values()].filter((s): s is SearchShard => s !== null);

  if (present.length === 0) {
    // No index yet (fresh bucket): scan the hot set live.
    for (const f of await liveQuery(env, p, p.terms, null, NO_INDEX_LIMIT)) candidates.set(f.hit.key, f);
  } else {
    let keys = null as Set<string> | null; // null = every term ignored so far
    const active: string[] = [];
    let empty = false;
    for (const t of p.terms) {
      const shard = shards.get(shardPrefix(t));
      const list = shard && Object.hasOwn(shard.terms, t) ? shard.terms[t] : undefined;
      if (list && list.length === 0) continue; // too common: ignore this term
      active.push(t);
      if (!list) {
        empty = true; // absent from the index: matches nothing built
        continue;
      }
      const set = new Set(list);
      keys = keys === null ? set : new Set([...keys].filter((k) => set.has(k)));
    }
    if (!empty && keys !== null) {
      for (const k of keys) {
        const doc = present.map((s) => (Object.hasOwn(s.docs, k) ? s.docs[k] : undefined)).find(Boolean);
        if (doc && typeof doc.key === 'string' && typeof doc.title === 'string')
          candidates.set(k, {
            hit: { ...doc, summary: String(doc.summary ?? ''), exploited: Boolean(doc.exploited) },
            sources: [],
          });
      }
    }
    if (active.length > 0) {
      const builtAt = present.map((s) => s.builtAt).sort()[0] as string;
      for (const f of await liveQuery(env, p, active, builtAt, DELTA_LIMIT)) candidates.set(f.hit.key, f);
    }
  }

  const matched = [...candidates.values()].slice(0, MAX_CANDIDATES).filter((f) => passes(f.hit, p));
  sortHits(matched, p);
  const page = matched.slice(p.offset, p.offset + p.limit);
  return { ...(await hydrate(env, page)), total: matched.length };
}

/** One read for the page: fresh fields, and `sources` for credits. Gone or no-longer-hot keys drop out. */
async function hydrate(env: SearchEnv, page: Found[]): Promise<Omit<SearchResult, 'total'>> {
  if (page.length === 0) return { hits: [], sources: [] };
  const rows = await env.DB_VULNS.prepare(
    `SELECT ${COLS} FROM vulns WHERE hot = 1 AND key IN (${page.map(() => '?').join(', ')})`,
  )
    .bind(...page.map((f) => f.hit.key))
    .all<Row>();
  const fresh = new Map<string, Found>();
  for (const row of rows.results) {
    const f = rowToHit(row);
    if (f) fresh.set(f.hit.key, f);
  }
  const out = page.map((f) => fresh.get(f.hit.key)).filter((f): f is Found => f !== undefined);
  return { hits: out.map((f) => f.hit), sources: out.map((f) => f.sources) };
}
