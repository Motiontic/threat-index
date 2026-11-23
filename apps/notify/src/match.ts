import type { SavedSearchParams } from '@ti/core/account';
import { searchTerms } from '@ti/core/search';
import type { Change, Cursor } from './collect';
import type { Env } from './env';
import { D1_CHUNK, MAX_SAVED_SEARCHES } from './limits';

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
    inserts = [...watch, ...searches]; // watch first: a change matched both ways stays 'watch'
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
