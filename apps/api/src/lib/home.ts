import type { HomeChange, HomeCounts, HomeItem, HomeLists, HomeResponse } from '@ti/core/api';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { displayFor, parseStringArray, type ReadEnv } from './preview';
import { allVisible, placeholders, visibleSources, type WorldEnv } from './world';
import { listBreaches } from './world-breach';

/** Bindings the home route reads: every public read binding plus `ti_world`. */
export type HomeEnv = WorldEnv & ReadEnv;

export const HOME_LIMIT = 10;
/** Signals repeat per vulnerability (several sources), so read more than the limit and de-duplicate. */
const SIGNAL_WINDOW = 60;

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const NOT_MAL = "hot = 1 AND substr(key, 1, 4) != 'MAL-'";
const IS_MAL = "hot = 1 AND substr(key, 1, 4) = 'MAL-'";
// The same text as the partial indexes in vulns/0002, so every list and count reads an index.

/** `22 Nov` from an ISO date or timestamp; empty when it does not parse. */
export function dayMonth(iso: string | null | undefined): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso ?? '');
  const month = m ? MONTHS[Number(m[2]) - 1] : undefined;
  return m && month ? `${Number(m[3])} ${month}` : '';
}

const sourceName = (id: string): string => SOURCE_BY_ID.get(id)?.name ?? id;
const count = (row: { n: number } | null | undefined): number => row?.n ?? 0;

interface SignalRow {
  vuln_key: string;
  source: string;
  first_seen: string;
}
interface VulnRow {
  key: string;
  title: string;
  published: string | null;
  cvss: number | null;
  sources: string | null;
}
interface IncidentRow {
  source: string;
  incident_id: string;
  title: string;
  date: string | null;
}
interface ChangeRow {
  entity_key: string;
  kind: string;
  at: string;
  source: string | null;
}

/** Titles for vulnerability keys, in one query on the key index. */
async function titlesFor(env: HomeEnv, keys: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (keys.length === 0) return out;
  const rows =
    (
      await env.DB_VULNS.prepare(
        `SELECT key, title FROM vulns WHERE key IN (${placeholders(1, keys.length)})`,
      )
        .bind(...keys)
        .all<{ key: string; title: string }>()
    ).results ?? [];
  for (const r of rows) out.set(r.key, r.title);
  return out;
}

/** Newest signals of the given kinds (visible sources only), one per vulnerability, titled and with `signal`. */
async function signalItems(
  env: HomeEnv,
  kinds: string[],
  ids: string[],
  signal: (row: SignalRow) => string,
): Promise<HomeItem[]> {
  if (ids.length === 0) return [];
  const rows =
    (
      await env.DB_SIGNALS.prepare(
        `SELECT vuln_key, source, first_seen FROM signals
         WHERE kind IN (${placeholders(2, kinds.length)}) AND source IN (${placeholders(2 + kinds.length, ids.length)})
         ORDER BY first_seen DESC LIMIT ?1`,
      )
        .bind(SIGNAL_WINDOW, ...kinds, ...ids)
        .all<SignalRow>()
    ).results ?? [];
  const seen = new Set<string>();
  const picked: SignalRow[] = [];
  for (const r of rows) {
    if (seen.has(r.vuln_key)) continue;
    seen.add(r.vuln_key);
    picked.push(r);
    if (picked.length === HOME_LIMIT) break;
  }
  const titles = await titlesFor(
    env,
    picked.map((r) => r.vuln_key),
  );
  return picked.flatMap((r) => {
    const title = titles.get(r.vuln_key);
    if (title === undefined) return [];
    return [{ key: r.vuln_key, title, type: 'vuln' as const, date: r.first_seen, signal: signal(r) }];
  });
}

async function publishedItems(env: HomeEnv, mal: boolean): Promise<HomeItem[]> {
  const rows =
    (
      await env.DB_VULNS.prepare(
        `SELECT key, title, published, cvss, sources FROM vulns
         WHERE ${mal ? IS_MAL : NOT_MAL} AND published IS NOT NULL
         ORDER BY published DESC LIMIT ?1`,
      )
        .bind(HOME_LIMIT)
        .all<VulnRow>()
    ).results ?? [];
  return rows.map((r) => {
    const item: HomeItem = { key: r.key, title: r.title, type: mal ? 'mal' : 'vuln' };
    if (r.published) item.date = r.published;
    if (mal) {
      const first = parseStringArray(r.sources)[0];
      if (first) item.signal = sourceName(first);
    } else if (typeof r.cvss === 'number') item.signal = `CVSS ${r.cvss.toFixed(1)}`;
    return item;
  });
}

async function incidentItems(env: HomeEnv, ids: string[]): Promise<HomeItem[]> {
  if (ids.length === 0) return [];
  const rows =
    (
      await env.DB_WORLD.prepare(
        `SELECT source, incident_id, title, date FROM incidents
         WHERE kind = 'ai' AND gated = 0 AND source IN (${placeholders(2, ids.length)})
         ORDER BY date IS NULL, date DESC LIMIT ?1`,
      )
        .bind(HOME_LIMIT, ...ids)
        .all<IncidentRow>()
    ).results ?? [];
  return rows.map((r) => {
    const item: HomeItem = {
      key: r.incident_id,
      source: r.source,
      title: r.title,
      type: 'ai',
      signal: sourceName(r.source),
    };
    if (r.date) item.date = r.date;
    return item;
  });
}

async function changeItems(env: HomeEnv, ids: string[]): Promise<HomeChange[]> {
  const rows =
    (
      await env.DB_SIGNALS.prepare(
        `SELECT entity_key, kind, at, source FROM changes ORDER BY at DESC LIMIT ?1`,
      )
        .bind(HOME_LIMIT * 3)
        .all<ChangeRow>()
    ).results ?? [];
  // A change from a hidden source is not shown; one with no source is.
  const shown = rows.filter((r) => r.source === null || ids.includes(r.source)).slice(0, HOME_LIMIT);
  const titles = await titlesFor(
    env,
    shown.filter((r) => r.kind !== 'breach_notice').map((r) => r.entity_key),
  );
  return shown.map((r) => {
    const breach = r.kind === 'breach_notice';
    const out: HomeChange = { key: r.entity_key, kind: r.kind, at: r.at, type: breach ? 'breach' : 'vuln' };
    const title = titles.get(r.entity_key);
    if (title !== undefined) out.title = title;
    if (r.source !== null) out.source = r.source;
    return out;
  });
}

const FRAMEWORK_OF_SOURCE: Record<string, string> = {
  'mitre-attack': 'attack',
  'mitre-atlas': 'atlas',
  cwe: 'cwe',
  capec: 'capec',
};
const FRAMEWORK_SOURCES = Object.keys(FRAMEWORK_OF_SOURCE);

async function counts(env: HomeEnv, ids: string[], frameworkSources: string[]): Promise<HomeCounts> {
  const n = <T extends { n: number }>(p: D1PreparedStatement) => p.first<T>();
  const noIds = ids.length === 0;
  const [vulns, mal, exploited, exploits, breaches, ai, ops, techniques] = await Promise.all([
    n(env.DB_VULNS.prepare(`SELECT COUNT(*) AS n FROM vulns WHERE ${NOT_MAL}`)),
    n(env.DB_VULNS.prepare(`SELECT COUNT(*) AS n FROM vulns WHERE ${IS_MAL}`)),
    noIds
      ? null
      : n(
          env.DB_SIGNALS.prepare(
            `SELECT COUNT(DISTINCT vuln_key) AS n FROM signals WHERE kind = 'exploited_wild' AND source IN (${placeholders(1, ids.length)})`,
          ).bind(...ids),
        ),
    noIds
      ? null
      : n(
          env.DB_SIGNALS.prepare(
            `SELECT COUNT(DISTINCT vuln_key) AS n FROM signals WHERE kind IN ('public_exploit','poc') AND source IN (${placeholders(1, ids.length)})`,
          ).bind(...ids),
        ),
    noIds
      ? null
      : n(
          env.DB_WORLD.prepare(
            `SELECT COUNT(*) AS n FROM breach_events e WHERE EXISTS (SELECT 1 FROM breach_notices n WHERE n.company_key = e.company_key AND n.event_key = e.key AND n.source IN (${placeholders(1, ids.length)}))`,
          ).bind(...ids),
        ),
    noIds
      ? null
      : n(
          env.DB_WORLD.prepare(
            `SELECT COUNT(*) AS n FROM incidents WHERE kind = 'ai' AND gated = 0 AND source IN (${placeholders(1, ids.length)})`,
          ).bind(...ids),
        ),
    noIds
      ? null
      : n(
          env.DB_WORLD.prepare(
            `SELECT COUNT(*) AS n FROM incidents WHERE kind = 'cyber_op' AND gated = 0 AND source IN (${placeholders(1, ids.length)})`,
          ).bind(...ids),
        ),
    frameworkSources.length === 0
      ? null
      : n(
          env.DB_WORLD.prepare(
            `SELECT COUNT(*) AS n FROM techniques WHERE framework IN (${placeholders(1, frameworkSources.length)})`,
          ).bind(...frameworkSources.map((s) => FRAMEWORK_OF_SOURCE[s])),
        ),
  ]);
  return {
    vulnerabilities: count(vulns),
    exploited: count(exploited),
    exploits: count(exploits),
    breaches: count(breaches),
    aiIncidents: count(ai),
    cyberOperations: count(ops),
    maliciousPackages: count(mal),
    techniques: count(techniques),
  };
}

export async function buildHome(env: HomeEnv): Promise<HomeResponse> {
  const v = await visibleSources(env);
  const ids = allVisible(v);
  const fwDisplay = await displayFor(env.SETTINGS, FRAMEWORK_SOURCES);
  const frameworkSources = FRAMEWORK_SOURCES.filter((s) => fwDisplay.get(s) !== 'hidden');
  const [c, exploited, vulnerabilities, exploits, breaches, aiIncidents, maliciousPackages, changes] =
    await Promise.all([
      counts(env, ids, frameworkSources),
      signalItems(env, ['exploited_wild'], ids, (r) =>
        `${sourceName(r.source)} ${dayMonth(r.first_seen)}`.trim(),
      ),
      publishedItems(env, false),
      signalItems(env, ['public_exploit', 'poc'], ids, (r) => sourceName(r.source)),
      listBreaches(env, v, undefined, 1).then((r) =>
        r.items.slice(0, HOME_LIMIT).map((b): HomeItem => {
          const item: HomeItem = {
            key: b.key,
            title: b.company?.name ?? b.key,
            type: 'breach',
            signal: `${b.noticeCount} ${b.noticeCount === 1 ? 'notice' : 'notices'}`,
          };
          if (b.firstSeen) item.date = b.firstSeen;
          return item;
        }),
      ),
      incidentItems(env, ids),
      publishedItems(env, true),
      changeItems(env, ids),
    ]);
  const lists: HomeLists = { exploited, vulnerabilities, exploits, breaches, aiIncidents, maliciousPackages };
  return { counts: c, lists, changes };
}
