import type { SavedSearchParams } from '@ti/core/account';
import { searchTerms } from '@ti/core/search';
import type { Change, Cursor } from './collect';
import type { Env } from './env';
import {
  AFFECTED_KEYS_PER_QUERY,
  AFFECTED_ROWS_PER_QUERY,
  D1_CHUNK,
  MAX_PAIR_BYTES,
  MAX_QUEUED_PER_USER,
  MAX_SAVED_SEARCHES,
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

type AffectedRow = { ecosystem: string; name: string; source: string; source_id: string; vuln_key: string };

export interface PackageMatch {
  inserts: QueueInsert[];
  /** Package-kind changes whose matching did not finish: matched again next run, never skipped. */
  unmatched: Set<string>;
}

/**
 * Package watches: two D1 queries per run, however many changes there are.
 * (1) `affected` for the run's vuln keys and records (`json_each`, one statement);
 * (2) the watchers of the hit packages only (`json_each` joined to `watch_packages`, indexed by package).
 * Eligibility is the same as `matchWatch`. An OS watch (`Debian`) also matches rows stored with a release
 * (`Debian:12`). A user's triggers are their own plus `new_advisory`.
 *
 * `changes` is in the order to match. The matched set is always a prefix of it: if the watcher lookup would be
 * too large (`pairBytes`), the changes not reached come back in `unmatched` and the caller holds the cursor
 * before them. The first change always fits, so a run always makes progress. Hits are taken in change order.
 */
export async function matchPackages(
  env: Env,
  changes: Change[],
  pairBytes = MAX_PAIR_BYTES,
): Promise<PackageMatch> {
  const ordered = changes.filter((c) => PACKAGE_KINDS.has(c.kind));
  const none: PackageMatch = { inserts: [], unmatched: new Set() };
  if (ordered.length === 0) return none;

  const changePkgs = new Map<string, string[]>();
  const readSet = new Set<string>();
  let bytes = 2;
  const unmatched = new Set<string>();
  let cut = false;
  let matched = 0;
  let truncatedRows = 0;
  const matchedList: Change[] = [];
  let next = 0;
  // `affected` is read in ordered groups of about AFFECTED_KEYS_PER_QUERY keys or records, one group at a time, and
  // only while the pair budget lasts: a group's rows are dropped once its changes are matched.
  while (next < ordered.length && !cut) {
    const group: Change[] = [];
    const vulnKeys = new Set<string>();
    const records = new Map<string, [string, string]>();
    while (next < ordered.length) {
      const c = ordered[next] as Change;
      const r = c.kind === 'new_advisory' ? recordOf(c) : null;
      const isNew =
        c.kind !== 'new_advisory'
          ? !vulnKeys.has(c.entity_key)
          : !!r && !records.has(r.source + SEP + r.sourceId);
      if (group.length > 0 && isNew && vulnKeys.size + records.size >= AFFECTED_KEYS_PER_QUERY) break;
      if (c.kind !== 'new_advisory') vulnKeys.add(c.entity_key);
      else if (r) records.set(r.source + SEP + r.sourceId, [r.source, r.sourceId]);
      group.push(c);
      next++;
    }
    const rows =
      vulnKeys.size + records.size === 0
        ? []
        : (
            await env.DB_ADVISORIES.prepare(
              `SELECT ecosystem, name, source, source_id, vuln_key FROM affected
                 WHERE vuln_key IN (SELECT value FROM json_each(?1))
               UNION
               SELECT ecosystem, name, source, source_id, vuln_key FROM affected
                 WHERE (source, source_id) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?2))
               LIMIT ?3`,
            )
              .bind(
                JSON.stringify([...vulnKeys]),
                JSON.stringify([...records.values()]),
                AFFECTED_ROWS_PER_QUERY,
              )
              .all<AffectedRow>()
          ).results;
    if (rows.length >= AFFECTED_ROWS_PER_QUERY) truncatedRows += rows.length;
    const byVuln = new Map<string, AffectedRow[]>();
    const byRecord = new Map<string, AffectedRow[]>();
    const push = (m: Map<string, AffectedRow[]>, k: string, r: AffectedRow) => {
      const list = m.get(k);
      if (list) list.push(r);
      else m.set(k, [r]);
    };
    for (const r of rows) {
      push(byVuln, r.vuln_key, r);
      push(byRecord, r.source + SEP + r.source_id, r);
    }

    // Candidate watch keys per change, in change order: the exact ecosystem and the part before the first `:`.
    const keysOf = (c: Change): string[] => {
      let hits: AffectedRow[] = [];
      if (c.kind !== 'new_advisory') hits = byVuln.get(c.entity_key) ?? [];
      else {
        const r = recordOf(c);
        hits = r ? (byRecord.get(r.source + SEP + r.sourceId) ?? []) : [];
      }
      const out = new Set<string>();
      for (const h of hits) {
        out.add(h.ecosystem + SEP + h.name);
        out.add((h.ecosystem.split(':')[0] as string) + SEP + h.name);
      }
      return [...out];
    };
    for (const c of group) {
      if (cut) {
        unmatched.add(c.id);
        continue;
      }
      const keys = keysOf(c);
      const fresh = keys.filter((k) => !readSet.has(k));
      const size = fresh.reduce((n, k) => n + k.length + 8, 0);
      if (matched > 0 && bytes + size > pairBytes) {
        cut = true;
        unmatched.add(c.id);
        continue;
      }
      let take = fresh;
      if (matched === 0 && size > pairBytes) {
        // The first change alone is over the budget: match what fits, so the run still makes progress.
        let n = 2;
        take = [];
        for (const k of fresh) {
          n += k.length + 8;
          if (n > pairBytes) break;
          take.push(k);
        }
        console.log(
          JSON.stringify({
            event: 'notify.package_match_truncated',
            packages: fresh.length,
            kept: take.length,
          }),
        );
      }
      for (const k of take) readSet.add(k);
      bytes += take.reduce((n, k) => n + k.length + 8, 0);
      const mine = keys.filter((k) => readSet.has(k));
      if (mine.length > 0) changePkgs.set(c.id, mine);
      matched++;
      matchedList.push(c);
    }
  }
  for (let i = next; i < ordered.length; i++) unmatched.add((ordered[i] as Change).id);
  if (truncatedRows > 0)
    console.log(JSON.stringify({ event: 'notify.package_match_truncated', affectedRows: truncatedRows }));
  if (cut)
    console.log(
      JSON.stringify({
        event: 'notify.package_match_truncated',
        changes: ordered.length,
        unmatched: unmatched.size,
      }),
    );
  if (readSet.size === 0) return { inserts: [], unmatched };

  type Watcher = { userId: string; ecosystem: string; name: string; triggers: Set<string> };
  const watchers = new Map<string, Watcher[]>(); // package key → watching users
  const pairs = [...readSet].map((k) => k.split(SEP));
  const found = (
    await env.DB_USERS.prepare(
      `SELECT w.user_id, w.ecosystem, w.name, u.alert_triggers
       FROM json_each(?1) j
       JOIN watch_packages w ON w.ecosystem = json_extract(j.value, '$[0]') AND w.name = json_extract(j.value, '$[1]')
       JOIN users u ON u.id = w.user_id
       WHERE w.alerts_on = 1 AND ${ELIGIBLE} AND (u.alert_instant = 1 OR u.digest != 'off')
       ORDER BY w.user_id`,
    )
      .bind(JSON.stringify(pairs))
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

  const inserts: QueueInsert[] = [];
  const seen = new Set<string>(); // userId SEP changeId: a change is queued once per user
  for (const c of matchedList) {
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
  /** The late read hit its row limit: more late rows may be waiting. */
  lateFull?: boolean;
  /** Test hook: the size budget of the package watcher lookup. */
  pairBytes?: number;
}

/**
 * Orders changes for package matching: forward rows in `(at, id)` order (so the matched set is a prefix and the
 * cursor can stop after it), then late rows, `new_advisory` before other kinds.
 */
export function matchOrder(changes: Change[], forwardCount: number): Change[] {
  const forward = changes.slice(0, forwardCount);
  const late = changes.slice(forwardCount);
  return [
    ...forward,
    ...late.filter((c) => c.kind === 'new_advisory'),
    ...late.filter((c) => c.kind !== 'new_advisory'),
  ];
}

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
 * If package matching ran out of budget the cursor stops after the last forward change whose matching finished,
 * and the late-read lower bound stays at the first late change not matched. Returns the rows newly queued.
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
  const inserts: QueueInsert[] = [];
  let saved: Cursor = cursor;
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
    const ordered = matchOrder(changes, forwardCount);
    let packages: PackageMatch;
    try {
      packages = await matchPackages(env, ordered, ctx.pairBytes);
    } catch (err) {
      // Package matching alone is held back: entry-watch and saved-search alerts still go out, and the cursor
      // stops before the first package-kind change so the next run matches it again.
      console.log(
        JSON.stringify({
          event: 'notify.package_match_failed',
          changes: ordered.length,
          error: err instanceof Error ? err.name : 'error',
        }),
      );
      packages = {
        inserts: [],
        unmatched: new Set(ordered.filter((c) => PACKAGE_KINDS.has(c.kind)).map((c) => c.id)),
      };
    }
    // Entry watch first, then package watch, then saved search: a change is queued once per user (first wins).
    const seen = new Set<string>();
    for (const r of [...watch, ...packages.inserts, ...searches]) {
      const k = r.userId + SEP + r.changeId;
      if (seen.has(k)) continue;
      seen.add(k);
      inserts.push(r);
    }
    const keep = ctx.start ?? cursor;
    const firstWaiting = changes.slice(0, forwardCount).findIndex((c) => packages.unmatched.has(c.id));
    if (firstWaiting >= 0) {
      const prev = changes[firstWaiting - 1];
      saved = prev ? { at: prev.at, id: prev.id, ...(keep.since ? { since: keep.since } : {}) } : keep;
      console.log(
        JSON.stringify({ event: 'notify.cursor_held', waiting: packages.unmatched.size, at: saved.at }),
      );
    }
    // Late rows are read from this bound next run: the first one not matched, else past the last one read.
    const late = changes.slice(forwardCount);
    const firstLate = late.find((c) => packages.unmatched.has(c.id));
    const lateBound = firstLate ?? (ctx.lateFull ? late[late.length - 1] : undefined);
    saved = { ...saved, ...(lateBound ? { late: { at: lateBound.at, id: lateBound.id } } : {}) };
    if (!lateBound && saved.late) delete saved.late;
  } else if (saved.late) {
    saved = { at: saved.at, id: saved.id, ...(saved.since ? { since: saved.since } : {}) };
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
  stmts.push(
    env.DB_USERS.prepare(
      `INSERT INTO notify_state (name, value, updated_at) VALUES ('cursor', ?1, ?2)
       ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    ).bind(JSON.stringify(saved), at),
  );
  const results = await env.DB_USERS.batch(stmts);
  const added = results.slice(0, insertCount).reduce((n, r) => n + (r.meta.changes ?? 0), 0);
  const dropped = results.slice(insertCount, -1).reduce((n, r) => n + (r.meta.changes ?? 0), 0);
  if (dropped > 0) console.log(JSON.stringify({ event: 'notify.queue_capped', dropped }));
  return Math.max(0, added - dropped);
}
