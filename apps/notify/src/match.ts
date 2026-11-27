import type { SavedSearchParams } from '@ti/core/account';
import { searchTerms } from '@ti/core/search';
import type { Change, Cursor } from './collect';
import type { Env } from './env';
import {
  D1_CHUNK,
  MAX_MATCH_QUERIES,
  MAX_QUEUED_PER_USER,
  MAX_SAVED_SEARCHES,
  MAX_WATCHED_PACKAGES,
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
/** Reserved for reading users in `matchPackages`; the rest of MAX_MATCH_QUERIES is for `affected`. */
const USER_QUERIES = 3;
const PAIRS_PER_QUERY = Math.floor(D1_CHUNK / 2);
/** Distinct watched packages one run reads users for. */
const MAX_HIT_PACKAGES = USER_QUERIES * PAIRS_PER_QUERY;

/** `new` of a `new_advisory` change is `<source>:<source_id>`. */
function recordOf(c: Change): { source: string; sourceId: string } | null {
  const at = c.new?.indexOf(':') ?? -1;
  return c.new && at > 0 && at < c.new.length - 1
    ? { source: c.new.slice(0, at), sourceId: c.new.slice(at + 1) }
    : null;
}

type AffectedRow = { ecosystem: string; name: string; source: string; source_id: string; vuln_key: string };

export interface PackageMatch {
  inserts: QueueInsert[];
  /** Package-kind changes whose matching did not finish (budget ran out): matched again next run, never skipped. */
  unmatched: Set<string>;
}

/**
 * Package watches. At most MAX_MATCH_QUERIES D1 queries per run, however many changes there are:
 * (1) the distinct watched set, (2) `affected` for the run's vuln keys and records, intersected in memory,
 * (3) the users of the hits. Eligibility is the same as `matchWatch`. An OS watch (`Debian`) also matches rows
 * stored with a release (`Debian:12`). A user's triggers are their own plus `new_advisory`.
 *
 * `changes` is in the order to match: `new_advisory` records first, then other kinds (forward rows before late
 * rows, so the cursor can always advance). Hits are processed in that change order. If the budget runs out, the
 * changes not reached are returned in `unmatched` and the caller holds the cursor before the first of them.
 */
export async function matchPackages(env: Env, changes: Change[]): Promise<PackageMatch> {
  const ordered = changes.filter((c) => PACKAGE_KINDS.has(c.kind));
  const none: PackageMatch = { inserts: [], unmatched: new Set() };
  if (ordered.length === 0) return none;
  let queries = 0;
  const watchedRows = (
    await env.DB_USERS.prepare(
      'SELECT DISTINCT ecosystem, name FROM watch_packages WHERE alerts_on = 1 ORDER BY ecosystem, name LIMIT ?1',
    )
      .bind(MAX_WATCHED_PACKAGES + 1)
      .all<{ ecosystem: string; name: string }>()
  ).results;
  queries++;
  if (watchedRows.length === 0) return none;
  if (watchedRows.length > MAX_WATCHED_PACKAGES)
    console.log(JSON.stringify({ event: 'notify.watch_set_large', limit: MAX_WATCHED_PACKAGES }));
  const watched = new Set(watchedRows.slice(0, MAX_WATCHED_PACKAGES).map((r) => r.ecosystem + SEP + r.name));

  // Lookups: a vuln key (`v` + key) or a record (`r` + source SEP source_id). Each change has one.
  const lookupOf = (c: Change): string | null => {
    if (c.kind !== 'new_advisory') return `v${c.entity_key}`;
    const rec = recordOf(c);
    return rec ? `r${rec.source}${SEP}${rec.sourceId}` : null;
  };
  const byLookup = new Map<string, Change[]>();
  for (const c of ordered) {
    const k = lookupOf(c);
    if (k) byLookup.set(k, [...(byLookup.get(k) ?? []), c]);
  }
  // Chunks in the order of the first change each holds.
  const firstIndex = new Map<string, number>();
  ordered.forEach((c, i) => {
    const k = lookupOf(c);
    if (k && !firstIndex.has(k)) firstIndex.set(k, i);
  });
  const lookups = [...byLookup.keys()];
  const vulnLookups = lookups.filter((k) => k.startsWith('v'));
  const recLookups = lookups.filter((k) => k.startsWith('r'));
  const chunkList = [...chunks(vulnLookups, D1_CHUNK), ...chunks(recLookups, PAIRS_PER_QUERY)].sort(
    (x, y) => (firstIndex.get(x[0] as string) ?? 0) - (firstIndex.get(y[0] as string) ?? 0),
  );

  const changePkgs = new Map<string, string[]>(); // change id → watched package keys it touches, in order
  const hit = (eco: string, name: string, cs: Change[]) => {
    const base = eco.split(':')[0] as string;
    for (const k of new Set([eco + SEP + name, base + SEP + name])) {
      if (!watched.has(k)) continue;
      for (const c of cs) {
        const list = changePkgs.get(c.id) ?? [];
        if (!list.includes(k)) list.push(k);
        changePkgs.set(c.id, list);
      }
    }
  };
  const unmatched = new Set<string>();
  const affectedBudget = MAX_MATCH_QUERIES - queries - USER_QUERIES;
  let used = 0;
  let truncated = false;
  for (const part of chunkList) {
    if (used >= affectedBudget) {
      truncated = true;
      for (const k of part) for (const c of byLookup.get(k) ?? []) unmatched.add(c.id);
      continue;
    }
    used++;
    const isVuln = (part[0] as string).startsWith('v');
    const rows = isVuln
      ? (
          await env.DB_ADVISORIES.prepare(
            `SELECT DISTINCT ecosystem, name, source, source_id, vuln_key FROM affected WHERE vuln_key IN (${marks(part.length)})`,
          )
            .bind(...part.map((k) => k.slice(1)))
            .all<AffectedRow>()
        ).results
      : (
          await env.DB_ADVISORIES.prepare(
            `SELECT DISTINCT ecosystem, name, source, source_id, vuln_key FROM affected
             WHERE (source, source_id) IN (VALUES ${part.map((_, i) => `(?${i * 2 + 1}, ?${i * 2 + 2})`).join(',')})`,
          )
            .bind(...part.flatMap((k) => k.slice(1).split(SEP)))
            .all<AffectedRow>()
        ).results;
    for (const r of rows)
      hit(
        r.ecosystem,
        r.name,
        byLookup.get(isVuln ? `v${r.vuln_key}` : `r${r.source}${SEP}${r.source_id}`) ?? [],
      );
  }
  queries += used;
  if (truncated) console.log(JSON.stringify({ event: 'notify.package_match_truncated', queries }));

  // Which hit packages this run reads users for: in change order, a change is matched only if all of its
  // packages fit. The first that doesn't, and every later change with hits, waits for the next run.
  const readSet: string[] = [];
  const inRead = new Set<string>();
  const matched: Change[] = [];
  let cut = false;
  for (const c of ordered) {
    const pkgs = changePkgs.get(c.id);
    if (!pkgs || unmatched.has(c.id)) continue;
    const fresh = pkgs.filter((k) => !inRead.has(k));
    if (cut || (readSet.length > 0 && readSet.length + fresh.length > MAX_HIT_PACKAGES)) {
      cut = true;
      unmatched.add(c.id);
      continue;
    }
    for (const k of fresh.slice(0, MAX_HIT_PACKAGES - readSet.length)) {
      inRead.add(k);
      readSet.push(k);
    }
    matched.push(c);
  }
  if (cut) console.log(JSON.stringify({ event: 'notify.package_match_truncated', queries }));
  if (matched.length === 0) return { inserts: [], unmatched };

  type Watcher = { userId: string; ecosystem: string; name: string; triggers: Set<string> };
  const watchers = new Map<string, Watcher[]>(); // package key → watching users, by user id
  const pairs = readSet.map((k) => k.split(SEP) as [string, string]);
  for (const part of chunks(pairs, PAIRS_PER_QUERY)) {
    const rows = (
      await env.DB_USERS.prepare(
        `SELECT w.user_id, w.ecosystem, w.name, u.alert_triggers FROM watch_packages w JOIN users u ON u.id = w.user_id
         WHERE w.alerts_on = 1 AND ${ELIGIBLE} AND (u.alert_instant = 1 OR u.digest != 'off')
         AND (w.ecosystem, w.name) IN (VALUES ${part.map((_, i) => `(?${i * 2 + 1}, ?${i * 2 + 2})`).join(',')})
         ORDER BY w.user_id`,
      )
        .bind(...part.flat())
        .all<{ user_id: string; ecosystem: string; name: string; alert_triggers: string }>()
    ).results;
    for (const r of rows) {
      const triggers = parseTriggers(r.alert_triggers);
      triggers.add('new_advisory'); // a package watch exists to hear about new advisories
      const k = r.ecosystem + SEP + r.name;
      watchers.set(k, [
        ...(watchers.get(k) ?? []),
        { userId: r.user_id, ecosystem: r.ecosystem, name: r.name, triggers },
      ]);
    }
  }

  const inserts: QueueInsert[] = [];
  const seen = new Set<string>(); // userId SEP changeId: a change is queued once per user
  for (const c of matched) {
    for (const k of changePkgs.get(c.id) ?? []) {
      for (const w of watchers.get(k) ?? []) {
        const key = w.userId + SEP + c.id;
        if (!w.triggers.has(c.kind) || seen.has(key)) continue;
        seen.add(key);
        inserts.push({ userId: w.userId, changeId: c.id, via: `pkg:${w.ecosystem}/${w.name}` });
      }
    }
  }
  return { inserts, unmatched };
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

/** What `collect` read, for `matchAndQueue`: the cursor to save and where the forward rows end. */
export interface MatchContext {
  /** Changes before this index are forward rows, the rest late rows. Default: all forward. */
  forwardCount?: number;
  /** The cursor the run started from: kept when no forward change finished matching. */
  start?: Cursor;
}

/**
 * Orders changes for package matching: the first forward change always leads (so each run finishes it and the
 * cursor advances, whatever the budget); then forward rows before late ones, `new_advisory` before other kinds.
 */
export function matchOrder(changes: Change[], forwardCount: number): Change[] {
  const rank = (c: Change, i: number) =>
    i === 0 && forwardCount > 0 ? -1 : (i < forwardCount ? 0 : 2) + (c.kind === 'new_advisory' ? 0 : 1);
  return changes
    .map((c, i) => ({ c, i, r: rank(c, i) }))
    .sort((x, y) => x.r - y.r || x.i - y.i)
    .map((x) => x.c);
}

/**
 * Keeps one insert per user and change, drops those already queued or sent (late rows read again), and caps
 * each user's queue at MAX_QUEUED_PER_USER. Returns the rows to insert and how many the cap dropped.
 */
async function queueable(env: Env, inserts: QueueInsert[]): Promise<{ rows: QueueInsert[]; capped: number }> {
  if (inserts.length === 0) return { rows: [], capped: 0 };
  const handled = new Set<string>();
  for (const part of chunks([...new Set(inserts.map((r) => r.changeId))]))
    for (const table of ['alert_queue', 'alerts_sent'])
      for (const r of (
        await env.DB_USERS.prepare(
          `SELECT user_id, change_id FROM ${table} WHERE change_id IN (${marks(part.length)})`,
        )
          .bind(...part)
          .all<{ user_id: string; change_id: string }>()
      ).results)
        handled.add(r.user_id + SEP + r.change_id);
  const fresh: QueueInsert[] = [];
  for (const r of inserts) {
    const k = r.userId + SEP + r.changeId;
    if (handled.has(k)) continue;
    handled.add(k);
    fresh.push(r);
  }
  const have = new Map<string, number>();
  for (const part of chunks([...new Set(fresh.map((r) => r.userId))]))
    for (const r of (
      await env.DB_USERS.prepare(
        `SELECT user_id, COUNT(*) AS n FROM alert_queue WHERE user_id IN (${marks(part.length)}) GROUP BY user_id`,
      )
        .bind(...part)
        .all<{ user_id: string; n: number }>()
    ).results)
      have.set(r.user_id, r.n);
  const rows: QueueInsert[] = [];
  let capped = 0;
  for (const r of fresh) {
    const n = have.get(r.userId) ?? 0;
    if (n >= MAX_QUEUED_PER_USER) {
      capped++;
      continue;
    }
    have.set(r.userId, n + 1);
    rows.push(r);
  }
  return { rows, capped };
}

/**
 * Matches changes to watch rows and saved searches, queues them (skipping anything already queued or sent, and
 * anything over a user's cap) and saves the cursor in the same batch. If package matching ran out of budget the
 * cursor stops after the last forward change whose matching finished. Returns the number of rows newly queued.
 */
export async function matchAndQueue(
  env: Env,
  changes: Change[],
  cursor: Cursor,
  runAt: Date,
  ctx: MatchContext = {},
): Promise<number> {
  const at = runAt.toISOString();
  const forwardCount = ctx.forwardCount ?? changes.length;
  let inserts: QueueInsert[] = [];
  let saved = cursor;
  if (changes.length > 0) {
    const byEntity = new Map<string, Change[]>();
    for (const c of changes) byEntity.set(c.entity_key, [...(byEntity.get(c.entity_key) ?? []), c]);
    const watch = await matchWatch(env, byEntity);
    const docs = await loadDocs(env, changes);
    const searches = await matchSearches(env, changes, docs);
    const packages = await matchPackages(env, matchOrder(changes, forwardCount));
    // Entry watch first, then package watch, then saved search: a change is queued once per user (first wins).
    inserts = [...watch, ...packages.inserts, ...searches];
    if (packages.unmatched.size > 0) {
      const firstWaiting = changes.slice(0, forwardCount).findIndex((c) => packages.unmatched.has(c.id));
      if (firstWaiting >= 0) {
        const prev = changes[firstWaiting - 1];
        const keep = ctx.start ?? cursor;
        saved = prev ? { at: prev.at, id: prev.id, ...(keep.since ? { since: keep.since } : {}) } : keep;
        console.log(
          JSON.stringify({ event: 'notify.cursor_held', waiting: packages.unmatched.size, at: saved.at }),
        );
      }
    }
  }
  const { rows, capped } = await queueable(env, inserts);
  if (capped > 0) console.log(JSON.stringify({ event: 'notify.queue_capped', dropped: capped }));
  const stmts = rows.map((r) =>
    env.DB_USERS.prepare(
      `INSERT OR IGNORE INTO alert_queue (user_id, change_id, created_at, via)
       SELECT ?1, ?2, ?3, ?4 WHERE NOT EXISTS (SELECT 1 FROM alerts_sent WHERE user_id = ?1 AND change_id = ?2)
         AND (SELECT COUNT(*) FROM alert_queue WHERE user_id = ?1) < ?5`,
    ).bind(r.userId, r.changeId, at, r.via, MAX_QUEUED_PER_USER),
  );
  stmts.push(
    env.DB_USERS.prepare(
      `INSERT INTO notify_state (name, value, updated_at) VALUES ('cursor', ?1, ?2)
       ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    ).bind(JSON.stringify(saved), at),
  );
  const results = await env.DB_USERS.batch(stmts);
  // The last statement is the cursor upsert.
  return results.slice(0, -1).reduce((n, r) => n + (r.meta.changes ?? 0), 0);
}
