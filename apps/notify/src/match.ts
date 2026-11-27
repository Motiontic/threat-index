import type { SavedSearchParams } from '@ti/core/account';
import { searchTerms } from '@ti/core/search';
import type { Change, Cursor } from './collect';
import type { Env } from './env';
import { D1_CHUNK, MAX_MATCH_QUERIES, MAX_SAVED_SEARCHES, MAX_WATCHED_PACKAGES } from './limits';

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

/**
 * Package watches. At most MAX_MATCH_QUERIES D1 queries per run, however many changes there are:
 * (1) the distinct watched set, (2) `affected` for the run's vuln keys and records, intersected in memory,
 * (3) the users of the hits. Eligibility is the same as `matchWatch`. An OS watch (`Debian`) also matches rows
 * stored with a release (`Debian:12`). A user's triggers are their own plus `new_advisory`.
 */
export async function matchPackages(env: Env, changes: Change[]): Promise<QueueInsert[]> {
  const wanted = changes.filter((c) => PACKAGE_KINDS.has(c.kind));
  if (wanted.length === 0) return [];
  let queries = 0;
  const watchedRows = (
    await env.DB_USERS.prepare(
      'SELECT DISTINCT ecosystem, name FROM watch_packages WHERE alerts_on = 1 LIMIT ?1',
    )
      .bind(MAX_WATCHED_PACKAGES + 1)
      .all<{ ecosystem: string; name: string }>()
  ).results;
  queries++;
  if (watchedRows.length === 0) return [];
  if (watchedRows.length > MAX_WATCHED_PACKAGES)
    console.log(JSON.stringify({ event: 'notify.watch_set_large', limit: MAX_WATCHED_PACKAGES }));
  const watched = new Set(watchedRows.slice(0, MAX_WATCHED_PACKAGES).map((r) => r.ecosystem + SEP + r.name));

  const vulnChanges = new Map<string, Change[]>(); // vuln_key → changes
  const recordChanges = new Map<string, Change[]>(); // source SEP source_id → changes
  for (const c of wanted) {
    if (c.kind === 'new_advisory') {
      const rec = recordOf(c);
      if (!rec) continue;
      const k = rec.source + SEP + rec.sourceId;
      recordChanges.set(k, [...(recordChanges.get(k) ?? []), c]);
    } else vulnChanges.set(c.entity_key, [...(vulnChanges.get(c.entity_key) ?? []), c]);
  }

  // Watched package → the changes that touch it.
  const hits = new Map<string, Change[]>();
  const hit = (eco: string, name: string, cs: Change[]) => {
    const base = eco.split(':')[0] as string;
    for (const k of new Set([eco + SEP + name, base + SEP + name])) {
      if (!watched.has(k)) continue;
      const list = hits.get(k) ?? [];
      for (const c of cs) if (!list.includes(c)) list.push(c);
      hits.set(k, list);
    }
  };
  // Keep a reserve of queries for the users read below.
  const USER_QUERIES = 3;
  const affectedBudget = MAX_MATCH_QUERIES - queries - USER_QUERIES;
  let used = 0;
  let truncated = false;
  const run = async <T>(
    parts: T[][],
    query: (
      part: T[],
    ) => Promise<{ ecosystem: string; name: string; source: string; source_id: string; vuln_key: string }[]>,
    on: (r: Awaited<ReturnType<typeof query>>[number]) => void,
  ) => {
    for (const part of parts) {
      if (used >= affectedBudget) {
        truncated = true;
        return;
      }
      used++;
      for (const r of await query(part)) on(r);
    }
  };
  type AffectedRow = { ecosystem: string; name: string; source: string; source_id: string; vuln_key: string };
  const vulnKeys = [...vulnChanges.keys()];
  await run(
    chunks(vulnKeys, D1_CHUNK),
    async (part) =>
      (
        await env.DB_ADVISORIES.prepare(
          `SELECT DISTINCT ecosystem, name, source, source_id, vuln_key FROM affected WHERE vuln_key IN (${marks(part.length)})`,
        )
          .bind(...part)
          .all<AffectedRow>()
      ).results,
    (r) => hit(r.ecosystem, r.name, vulnChanges.get(r.vuln_key) ?? []),
  );
  const records = [...recordChanges.keys()].map((k) => k.split(SEP) as [string, string]);
  await run(
    chunks(records, D1_CHUNK / 2),
    async (part) =>
      (
        await env.DB_ADVISORIES.prepare(
          `SELECT DISTINCT ecosystem, name, source, source_id, vuln_key FROM affected
           WHERE (source, source_id) IN (VALUES ${part.map((_, i) => `(?${i * 2 + 1}, ?${i * 2 + 2})`).join(',')})`,
        )
          .bind(...part.flat())
          .all<AffectedRow>()
      ).results,
    (r) => hit(r.ecosystem, r.name, recordChanges.get(r.source + SEP + r.source_id) ?? []),
  );
  queries += used;
  if (truncated) console.log(JSON.stringify({ event: 'notify.package_match_truncated', queries }));
  if (hits.size === 0) return [];

  const out: QueueInsert[] = [];
  const pairs = [...hits.keys()].sort().map((k) => k.split(SEP) as [string, string]);
  const userParts = chunks(pairs, D1_CHUNK / 2);
  if (userParts.length > USER_QUERIES)
    console.log(JSON.stringify({ event: 'notify.package_match_truncated', queries }));
  const seen = new Set<string>(); // userId SEP changeId: a change is queued once per user
  for (const part of userParts.slice(0, USER_QUERIES)) {
    const rows = (
      await env.DB_USERS.prepare(
        `SELECT w.user_id, w.ecosystem, w.name, u.alert_triggers FROM watch_packages w JOIN users u ON u.id = w.user_id
         WHERE w.alerts_on = 1 AND ${ELIGIBLE} AND (u.alert_instant = 1 OR u.digest != 'off')
         AND (w.ecosystem, w.name) IN (VALUES ${part.map((_, i) => `(?${i * 2 + 1}, ?${i * 2 + 2})`).join(',')})
         ORDER BY w.user_id, w.ecosystem, w.name`,
      )
        .bind(...part.flat())
        .all<{ user_id: string; ecosystem: string; name: string; alert_triggers: string }>()
    ).results;
    for (const r of rows) {
      const triggers = parseTriggers(r.alert_triggers);
      triggers.add('new_advisory'); // a package watch exists to hear about new advisories
      for (const c of hits.get(r.ecosystem + SEP + r.name) ?? []) {
        const k = r.user_id + SEP + c.id;
        if (!triggers.has(c.kind) || seen.has(k)) continue;
        seen.add(k);
        out.push({ userId: r.user_id, changeId: c.id, via: `pkg:${r.ecosystem}/${r.name}` });
      }
    }
  }
  return out;
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

/**
 * Matches changes to watch rows and saved searches, queues them (skipping anything already sent) and saves
 * the cursor in the same batch. Returns the number of rows newly queued.
 */
export async function matchAndQueue(
  env: Env,
  changes: Change[],
  cursor: Cursor,
  runAt: Date,
): Promise<number> {
  const at = runAt.toISOString();
  let inserts: QueueInsert[] = [];
  if (changes.length > 0) {
    const byEntity = new Map<string, Change[]>();
    for (const c of changes) byEntity.set(c.entity_key, [...(byEntity.get(c.entity_key) ?? []), c]);
    const watch = await matchWatch(env, byEntity);
    const docs = await loadDocs(env, changes);
    const searches = await matchSearches(env, changes, docs);
    const packages = await matchPackages(env, changes);
    // Entry watch first, then package watch, then saved search: a change is queued once per user (first wins).
    inserts = [...watch, ...packages, ...searches];
  }
  const stmts = inserts.map((r) =>
    env.DB_USERS.prepare(
      `INSERT OR IGNORE INTO alert_queue (user_id, change_id, created_at, via)
       SELECT ?1, ?2, ?3, ?4 WHERE NOT EXISTS (SELECT 1 FROM alerts_sent WHERE user_id = ?1 AND change_id = ?2)`,
    ).bind(r.userId, r.changeId, at, r.via),
  );
  stmts.push(
    env.DB_USERS.prepare(
      `INSERT INTO notify_state (name, value, updated_at) VALUES ('cursor', ?1, ?2)
       ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    ).bind(JSON.stringify(cursor), at),
  );
  const results = await env.DB_USERS.batch(stmts);
  // The last statement is the cursor upsert.
  return results.slice(0, -1).reduce((n, r) => n + (r.meta.changes ?? 0), 0);
}
