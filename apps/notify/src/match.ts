import type { SavedSearchParams } from '@ti/core/account';
import { searchTerms } from '@ti/core/search';
import type { Change, Cursor } from './collect';
import type { Env } from './env';
import {
  D1_CHUNK,
  MAX_PACKAGE_PAIRS,
  MAX_QUEUED_PER_USER,
  MAX_SAVED_SEARCHES,
  PACKAGE_KEYS_PER_CHUNK,
  WATCHER_PAIRS_PER_QUERY,
} from './limits';

export const DEFAULT_TRIGGERS = [
  'newly_exploited',
  'public_exploit',
  'epss_band',
  'fix_released',
  'breach_notice',
];

export interface QueueInsert {
  userId: string;
  changeId: string;
  via: string;
}

export interface EntityDoc {
  type: 'vuln' | 'breach';
  key: string;
  title: string; // vuln title or company name
  summary: string;
  cvss: number | null;
  kevAdded: string | null;
  published: string | null;
}

export interface SearchSpec {
  query: string;
  params: SavedSearchParams;
}

export function parseTriggers(raw: string | null | undefined): Set<string> {
  try {
    const j: unknown = JSON.parse(raw ?? '');
    if (Array.isArray(j) && j.every((x) => typeof x === 'string')) return new Set(j as string[]);
  } catch {}
  return new Set(DEFAULT_TRIGGERS);
}

const SEV: Record<string, (c: number) => boolean> = {
  critical: (c) => c >= 9,
  high: (c) => c >= 7 && c < 9,
  medium: (c) => c >= 4 && c < 7,
  low: (c) => c > 0 && c < 4,
};

export function parseParams(raw: string | null | undefined): SavedSearchParams {
  try {
    const j = JSON.parse(raw ?? '{}') as Record<string, unknown>;
    const arr = (v: unknown) =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : undefined;
    return { type: arr(j.type), sig: arr(j.sig), sev: arr(j.sev), year: arr(j.year) };
  } catch {
    return {};
  }
}

/** Same filters as the search route: repeated values of one filter are OR'd, different filters AND'd. */
export function matchesSearch(search: SearchSpec, doc: EntityDoc): boolean {
  const { type, sig, sev, year } = search.params;
  const terms = searchTerms(search.query).slice(0, 8);
  const hasFilter = [type, sig, sev, year].some((f) => f && f.length > 0);
  if (terms.length === 0 && !hasFilter) return false;
  if (terms.length > 0) {
    const have = new Set(searchTerms(`${doc.key} ${doc.title} ${doc.type === 'vuln' ? doc.summary : ''}`));
    if (!terms.every((t) => have.has(t))) return false;
  }
  if (type && type.length > 0 && !type.includes(doc.type)) return false;
  if (sig?.includes('kev') && !doc.kevAdded) return false;
  if (sev && sev.length > 0) {
    const c = doc.cvss;
    if (c === null || !sev.some((s) => SEV[s]?.(c))) return false;
  }
  if (year && year.length > 0 && !(doc.published && year.includes(doc.published.slice(0, 4)))) return false;
  return true;
}

function chunks<T>(xs: T[], n = D1_CHUNK): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}
const marks = (n: number) => Array.from({ length: n }, (_, i) => `?${i + 1}`).join(',');

const ELIGIBLE = "u.email_suppressed = 0 AND u.deleted_at IS NULL AND u.email != ''";

async function matchWatch(env: Env, byEntity: Map<string, Change[]>): Promise<QueueInsert[]> {
  const out: QueueInsert[] = [];
  for (const keys of chunks([...byEntity.keys()])) {
    const rows = (
      await env.DB_USERS.prepare(
        `SELECT w.user_id, w.entry_key, u.alert_triggers FROM watch w JOIN users u ON u.id = w.user_id
         WHERE w.alerts_on = 1 AND ${ELIGIBLE} AND (u.alert_instant = 1 OR u.digest != 'off')
         AND w.entry_key IN (${marks(keys.length)})`,
      )
        .bind(...keys)
        .all<{ user_id: string; entry_key: string; alert_triggers: string }>()
    ).results;
    for (const r of rows) {
      const triggers = parseTriggers(r.alert_triggers);
      for (const c of byEntity.get(r.entry_key) ?? [])
        if (triggers.has(c.kind)) out.push({ userId: r.user_id, changeId: c.id, via: 'watch' });
    }
  }
  return out;
}

/** The change kinds a package watch hears about. */
const PACKAGE_KINDS = new Set([
  'new_advisory',
  'newly_exploited',
  'public_exploit',
  'epss_band',
  'fix_released',
  'cvss_change',
]);
const SEP = '\u0000';

/** `new` of a `new_advisory` change is `<source>:<source_id>`. */
function recordOf(c: Change): { source: string; sourceId: string } | null {
  const at = c.new?.indexOf(':') ?? -1;
  return c.new && at > 0 && at < c.new.length - 1
    ? { source: c.new.slice(0, at), sourceId: c.new.slice(at + 1) }
    : null;
}

/** The base ecosystem (`Debian:12` → `Debian`) in SQL. */
const BASE_ECO =
  "CASE WHEN instr(ecosystem, ':') > 0 THEN substr(ecosystem, 1, instr(ecosystem, ':') - 1) ELSE ecosystem END";

/**
 * Package watches. No budget, prefix or hold: a run always finishes.
 * (1) Records of `new_advisory` changes first, then vuln keys, so at the cap new advisories are kept. `SELECT DISTINCT` base ecosystem and name from `affected` for the run's vuln keys and records, in chunks of
 *     PACKAGE_KEYS_PER_CHUNK (all chunks, every run). DISTINCT collapses distro releases, so a kernel CVE gives a
 *     few rows. At most MAX_PACKAGE_PAIRS distinct pairs are kept; past that no more chunks are read and
 *     `package_match_truncated` is logged (counts only).
 * (2) The watchers of those pairs through `watch_packages_by_package` (`json_each`, in chunks).
 * Eligibility is the same as `matchWatch`. A watch on `Debian` matches `Debian:12` because pairs use the base
 * ecosystem. A user's triggers are their own plus `new_advisory`. Hits are taken in change order.
 * The caller treats any error as "no package alerts this run".
 */
export async function matchPackages(
  env: Env,
  changes: Change[],
  maxPairs = MAX_PACKAGE_PAIRS,
): Promise<QueueInsert[]> {
  const relevant = changes.filter((c) => PACKAGE_KINDS.has(c.kind));
  if (relevant.length === 0) return [];

  const vulnKeys = [...new Set(relevant.filter((c) => c.kind !== 'new_advisory').map((c) => c.entity_key))];
  const recMap = new Map<string, [string, string]>();
  for (const c of relevant) {
    const r = c.kind === 'new_advisory' ? recordOf(c) : null;
    if (r) recMap.set(r.source + SEP + r.sourceId, [r.source, r.sourceId]);
  }
  const records = [...recMap.values()];

  const pairs = new Set<string>(); // base ecosystem SEP name
  const byVuln = new Map<string, Set<string>>();
  const byRecord = new Map<string, Set<string>>();
  let full = false;
  let seenRows = 0;
  const add = (m: Map<string, Set<string>>, k: string, p: string) => {
    const set = m.get(k);
    if (set) set.add(p);
    else m.set(k, new Set([p]));
  };
  const take = (eco: string, name: string): string | null => {
    const p = eco + SEP + name;
    if (!pairs.has(p)) {
      if (pairs.size >= maxPairs) {
        full = true;
        return null;
      }
      pairs.add(p);
    }
    return p;
  };
  for (const recs of chunks(records, PACKAGE_KEYS_PER_CHUNK)) {
    if (full) break;
    const rows = (
      await env.DB_ADVISORIES.prepare(
        `SELECT DISTINCT source, source_id, ${BASE_ECO} AS eco, name FROM affected
         WHERE (source, source_id) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?1))`,
      )
        .bind(JSON.stringify(recs))
        .all<{ source: string; source_id: string; eco: string; name: string }>()
    ).results;
    for (const r of rows) {
      seenRows++;
      const p = take(r.eco, r.name);
      if (p) add(byRecord, r.source + SEP + r.source_id, p);
    }
  }
  for (const keys of chunks(vulnKeys, PACKAGE_KEYS_PER_CHUNK)) {
    if (full) break;
    const rows = (
      await env.DB_ADVISORIES.prepare(
        `SELECT DISTINCT vuln_key, ${BASE_ECO} AS eco, name FROM affected
         WHERE vuln_key IN (SELECT value FROM json_each(?1))`,
      )
        .bind(JSON.stringify(keys))
        .all<{ vuln_key: string; eco: string; name: string }>()
    ).results;
    for (const r of rows) {
      seenRows++;
      const p = take(r.eco, r.name);
      if (p) add(byVuln, r.vuln_key, p);
    }
  }
  if (full)
    console.log(
      JSON.stringify({
        event: 'notify.package_match_truncated',
        pairs: pairs.size,
        rows: seenRows,
        changes: relevant.length,
      }),
    );
  if (pairs.size === 0) return [];

  type Watcher = { userId: string; ecosystem: string; name: string; triggers: Set<string> };
  const watchers = new Map<string, Watcher[]>(); // package key → watching users
  for (const part of chunks(
    [...pairs].map((k) => k.split(SEP)),
    WATCHER_PAIRS_PER_QUERY,
  )) {
    const found = (
      await env.DB_USERS.prepare(
        `SELECT w.user_id, w.ecosystem, w.name, u.alert_triggers
         FROM json_each(?1) j
         JOIN watch_packages w ON w.ecosystem = json_extract(j.value, '$[0]') AND w.name = json_extract(j.value, '$[1]')
         JOIN users u ON u.id = w.user_id
         WHERE w.alerts_on = 1 AND ${ELIGIBLE} AND (u.alert_instant = 1 OR u.digest != 'off')
         ORDER BY w.user_id`,
      )
        .bind(JSON.stringify(part))
        .all<{ user_id: string; ecosystem: string; name: string; alert_triggers: string }>()
    ).results;
    for (const r of found) {
      const triggers = parseTriggers(r.alert_triggers);
      triggers.add('new_advisory'); // a package watch exists to hear about new advisories
      const k = r.ecosystem + SEP + r.name;
      const w = { userId: r.user_id, ecosystem: r.ecosystem, name: r.name, triggers };
      const list = watchers.get(k);
      if (list) list.push(w);
      else watchers.set(k, [w]);
    }
  }
  if (watchers.size === 0) return [];

  const inserts: QueueInsert[] = [];
  const seen = new Set<string>(); // userId SEP changeId: a change is queued once per user
  for (const c of relevant) {
    let hit: Set<string> | undefined;
    if (c.kind !== 'new_advisory') hit = byVuln.get(c.entity_key);
    else {
      const r = recordOf(c);
      hit = r ? byRecord.get(r.source + SEP + r.sourceId) : undefined;
    }
    for (const k of hit ?? []) {
      for (const w of watchers.get(k) ?? []) {
        const key = w.userId + SEP + c.id;
        if (!w.triggers.has(c.kind) || seen.has(key)) continue;
        seen.add(key);
        inserts.push({ userId: w.userId, changeId: c.id, via: `pkg:${w.ecosystem}/${w.name}` });
      }
    }
  }
  return inserts;
}

/** The changed entities, for search matching and titles. Key → doc. */
export async function loadDocs(env: Env, changes: Change[]): Promise<Map<string, EntityDoc>> {
  const docs = new Map<string, EntityDoc>();
  const vulnKeys = [...new Set(changes.filter((c) => c.kind !== 'breach_notice').map((c) => c.entity_key))];
  const companyKeys = [
    ...new Set(changes.filter((c) => c.kind === 'breach_notice').map((c) => c.entity_key)),
  ];
  for (const keys of chunks(vulnKeys)) {
    const rows = (
      await env.DB_VULNS.prepare(
        `SELECT key, title, summary, cvss, kev_added, published FROM vulns WHERE key IN (${marks(keys.length)})`,
      )
        .bind(...keys)
        .all<{
          key: string;
          title: string;
          summary: string | null;
          cvss: number | null;
          kev_added: string | null;
          published: string | null;
        }>()
    ).results;
    for (const r of rows)
      docs.set(r.key, {
        type: 'vuln',
        key: r.key,
        title: r.title,
        summary: r.summary ?? '',
        cvss: r.cvss,
        kevAdded: r.kev_added,
        published: r.published,
      });
  }
  for (const keys of chunks(companyKeys)) {
    const rows = (
      await env.DB_WORLD.prepare(`SELECT key, name FROM companies WHERE key IN (${marks(keys.length)})`)
        .bind(...keys)
        .all<{ key: string; name: string }>()
    ).results;
    for (const r of rows)
      docs.set(r.key, {
        type: 'breach',
        key: r.key,
        title: r.name,
        summary: '',
        cvss: null,
        kevAdded: null,
        published: null,
      });
  }
  return docs;
}

async function matchSearches(
  env: Env,
  changes: Change[],
  docs: Map<string, EntityDoc>,
): Promise<QueueInsert[]> {
  const rows = (
    await env.DB_USERS.prepare(
      `SELECT s.user_id, s.id, s.query, s.params, u.alert_triggers FROM saved_searches s
       JOIN users u ON u.id = s.user_id
       WHERE s.alerts_on = 1 AND u.digest != 'off' AND ${ELIGIBLE} LIMIT ?1`,
    )
      .bind(MAX_SAVED_SEARCHES + 1)
      .all<{ user_id: string; id: string; query: string; params: string; alert_triggers: string }>()
  ).results;
  if (rows.length > MAX_SAVED_SEARCHES)
    console.log(JSON.stringify({ event: 'notify.searches_truncated', limit: MAX_SAVED_SEARCHES }));
  const out: QueueInsert[] = [];
  for (const s of rows.slice(0, MAX_SAVED_SEARCHES)) {
    const triggers = parseTriggers(s.alert_triggers);
    const spec: SearchSpec = { query: s.query, params: parseParams(s.params) };
    for (const c of changes) {
      if (!triggers.has(c.kind)) continue;
      const doc = docs.get(c.entity_key);
      if (doc && matchesSearch(spec, doc))
        out.push({ userId: s.user_id, changeId: c.id, via: `search:${s.id}` });
    }
  }
  return out;
}

/** Test hook for `matchAndQueue`. */
export interface MatchContext {
  /** Test hook: the distinct-pair cap of package matching. */
  maxPairs?: number;
}

/** Statements per D1 batch. */
export const MAX_BATCH_STATEMENTS = 500;
/** Rows per insert statement. */
const INSERT_CHUNK = 200;
/** Queue order: entry watch, then package watch, then saved search. */
const CLASS_SQL = "CASE WHEN via = 'watch' THEN 0 WHEN via LIKE 'pkg:%' THEN 1 ELSE 2 END";

/**
 * Matches changes to watch rows and saved searches, queues them and saves the cursor in the same batch.
 * Rows go in with `INSERT OR IGNORE` (already queued, or already sent, is skipped). Then each touched user is
 * cut back to MAX_QUEUED_PER_USER: watch rows are kept before saved-search rows; among saved-search rows the
 * ones queued by this run go first, then the oldest. The oldest watch row goes only when the user has more
 * watch rows than the cap.
 * The cursor always advances past every change read. Returns the rows newly queued.
 */
export async function matchAndQueue(
  env: Env,
  changes: Change[],
  cursor: Cursor,
  runAt: Date,
  ctx: MatchContext = {},
): Promise<number> {
  const at = runAt.toISOString();
  const inserts: QueueInsert[] = [];
  if (changes.length > 0) {
    const byEntity = new Map<string, Change[]>();
    for (const c of changes) {
      const list = byEntity.get(c.entity_key);
      if (list) list.push(c);
      else byEntity.set(c.entity_key, [c]);
    }
    const watch = await matchWatch(env, byEntity);
    const docs = await loadDocs(env, changes);
    const searches = await matchSearches(env, changes, docs);
    let packages: QueueInsert[] = [];
    try {
      packages = await matchPackages(env, changes, ctx.maxPairs);
    } catch (err) {
      // Package alerts are skipped for this run; entry-watch and saved-search alerts go out and the cursor advances.
      console.log(
        JSON.stringify({
          event: 'notify.package_match_failed',
          changes: changes.length,
          error: err instanceof Error ? err.name : 'error',
        }),
      );
    }
    // Entry watch first, then package watch, then saved search: a change is queued once per user (first wins).
    // At most MAX_QUEUED_PER_USER rows per user are kept in memory, in that class order.
    const seen = new Set<string>();
    const perUser = new Map<string, number>();
    let overCap = 0;
    for (const group of [watch, packages, searches])
      for (const r of group) {
        const k = r.userId + SEP + r.changeId;
        if (seen.has(k)) continue;
        seen.add(k);
        const n = perUser.get(r.userId) ?? 0;
        if (n >= MAX_QUEUED_PER_USER) {
          overCap++;
          continue;
        }
        perUser.set(r.userId, n + 1);
        inserts.push(r);
      }
    if (overCap > 0) console.log(JSON.stringify({ event: 'notify.queue_capped', dropped: overCap }));
  }
  const stmts: D1PreparedStatement[] = [];
  for (let i = 0; i < inserts.length; i += INSERT_CHUNK)
    stmts.push(
      env.DB_USERS.prepare(
        `INSERT OR IGNORE INTO alert_queue (user_id, change_id, created_at, via)
         SELECT json_extract(j.value, '$[0]'), json_extract(j.value, '$[1]'), ?2, json_extract(j.value, '$[2]')
         FROM json_each(?1) j
         WHERE NOT EXISTS (SELECT 1 FROM alerts_sent s
                           WHERE s.user_id = json_extract(j.value, '$[0]') AND s.change_id = json_extract(j.value, '$[1]'))`,
      ).bind(
        JSON.stringify(inserts.slice(i, i + INSERT_CHUNK).map((r) => [r.userId, r.changeId, r.via])),
        at,
      ),
    );
  const users = [...new Set(inserts.map((r) => r.userId))];
  for (let i = 0; i < users.length; i += 500)
    stmts.push(
      env.DB_USERS.prepare(
        `DELETE FROM alert_queue WHERE (user_id, change_id) IN (
           SELECT user_id, change_id FROM (
             SELECT user_id, change_id, ROW_NUMBER() OVER (
               PARTITION BY user_id
               ORDER BY ${CLASS_SQL} = 2, CASE WHEN ${CLASS_SQL} < 2 THEN created_at END DESC,
                        CASE WHEN ${CLASS_SQL} = 2 AND created_at = ?3 THEN 1 ELSE 0 END,
                        CASE WHEN ${CLASS_SQL} = 2 THEN created_at END DESC, change_id DESC) AS rn
             FROM alert_queue WHERE user_id IN (SELECT value FROM json_each(?1))
           ) WHERE rn > ?2)`,
      ).bind(JSON.stringify(users.slice(i, i + 500)), MAX_QUEUED_PER_USER, at),
    );
  const insertCount = Math.ceil(inserts.length / INSERT_CHUNK);
  const cursorStmt = env.DB_USERS.prepare(
    `INSERT INTO notify_state (name, value, updated_at) VALUES ('cursor', ?1, ?2)
     ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
  ).bind(JSON.stringify(cursor), at);
  // Batches of at most MAX_BATCH_STATEMENTS. The cursor goes in the last batch, after every insert, so a failure
  // before it just retries the window (inserts are idempotent through the alert_queue key).
  const batches = chunks(stmts, MAX_BATCH_STATEMENTS - 1);
  if (batches.length === 0) batches.push([]);
  const lastBatch = batches[batches.length - 1];
  if (lastBatch) lastBatch.push(cursorStmt);
  const results: D1Result[] = [];
  for (const b of batches) results.push(...(await env.DB_USERS.batch(b)));
  const added = results.slice(0, insertCount).reduce((n, r) => n + (r.meta.changes ?? 0), 0);
  const dropped = results.slice(insertCount, -1).reduce((n, r) => n + (r.meta.changes ?? 0), 0);
  if (dropped > 0) console.log(JSON.stringify({ event: 'notify.queue_capped', dropped }));
  return Math.max(0, added - dropped);
}
