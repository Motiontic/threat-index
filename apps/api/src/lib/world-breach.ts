import type { BreachCount, BreachDetail, BreachNotice, BreachSummary, CountUnit } from '@ti/core/world-api';
import { creditsFor } from './credits';
import { displayFor, parseStringArray } from './preview';
import {
  allVisible,
  likePattern,
  optional,
  PAGE_SIZE,
  placeholders,
  safeUrl,
  type Visible,
  type WorldEnv,
} from './world';

export interface NoticeRow {
  source: string;
  notice_id: string;
  company_key: string | null;
  raw_name: string;
  occurred_from: string | null;
  occurred_to: string | null;
  discovered: string | null;
  notified: string | null;
  count: number | null;
  count_unit: string;
  jurisdiction: string | null;
  data_types: string | null;
  url: string | null;
  event_key: string | null;
}
interface EventRow {
  key: string;
  company_key: string | null;
  first_seen: string;
  dates: string | null;
  company_name: string | null;
}

const UNITS: readonly string[] = ['state_residents', 'individuals', 'accounts', 'not_stated', 'claim'];
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** One entry per (unit, jurisdiction): the largest count among `full` notices. Counts are never added. */
export function breachCounts(rows: { row: NoticeRow; mode: 'full' | 'link' }[]): BreachCount[] {
  const best = new Map<string, BreachCount>();
  for (const { row, mode } of rows) {
    if (mode !== 'full' || typeof row.count !== 'number' || !UNITS.includes(row.count_unit)) continue;
    const jurisdiction = row.jurisdiction ?? null;
    const k = `${row.count_unit}\u0000${jurisdiction ?? ''}`;
    const cur = best.get(k);
    if (!cur || row.count > cur.count)
      best.set(k, { unit: row.count_unit as CountUnit, jurisdiction, count: row.count });
  }
  return [...best.values()].sort(
    (a, b) => cmp(a.unit, b.unit) || cmp(a.jurisdiction ?? '', b.jurisdiction ?? ''),
  );
}

export function toNotice(row: NoticeRow, mode: 'full' | 'link'): BreachNotice {
  const out: BreachNotice = {
    source: row.source,
    noticeId: row.notice_id,
    name: row.raw_name,
    display: mode,
  };
  const notified = optional(row.notified);
  if (notified !== undefined) out.notified = notified;
  const url = safeUrl(row.url);
  if (url !== undefined) out.url = url;
  if (mode === 'full') {
    const of = optional(row.occurred_from);
    if (of !== undefined) out.occurredFrom = of;
    const ot = optional(row.occurred_to);
    if (ot !== undefined) out.occurredTo = ot;
    const d = optional(row.discovered);
    if (d !== undefined) out.discovered = d;
    if (typeof row.count === 'number') out.count = row.count;
    if (UNITS.includes(row.count_unit)) out.countUnit = row.count_unit as CountUnit;
    const j = optional(row.jurisdiction);
    if (j !== undefined) out.jurisdiction = j;
    out.dataTypes = parseStringArray(row.data_types);
  }
  return out;
}

const earliest = (xs: (string | null | undefined)[]): string | undefined =>
  xs.reduce<string | undefined>((m, x) => (x && (m === undefined || x < m) ? x : m), undefined);

/**
 * Earliest `notified` among visible notices (as the linker does), else the earliest occurred/discovered date
 * of a `full` notice. The event row is only a last resort: it is built from hidden sources too.
 * `listBreaches` orders by the same rule in SQL.
 */
function visibleFirstSeen(ev: EventRow, notices: { row: NoticeRow; mode: 'full' | 'link' }[]): string {
  return (
    earliest(notices.map((n) => n.row.notified)) ??
    earliest(notices.flatMap((n) => (n.mode === 'full' ? [n.row.occurred_from ?? n.row.discovered] : []))) ??
    ev.first_seen
  );
}

/** The occurrence span of `full` notices only. */
function visibleDates(
  notices: { row: NoticeRow; mode: 'full' | 'link' }[],
): { from: string; to: string } | undefined {
  const full = notices.filter((n) => n.mode === 'full').map((n) => n.row);
  const from = earliest(full.map((r) => r.occurred_from));
  const to = full.reduce<string | undefined>(
    (m, r) => (r.occurred_to && (m === undefined || r.occurred_to > m) ? r.occurred_to : m),
    undefined,
  );
  return from && to ? { from, to } : undefined;
}

function summarise(ev: EventRow, notices: { row: NoticeRow; mode: 'full' | 'link' }[]): BreachSummary {
  const out: BreachSummary = {
    key: ev.key,
    company: ev.company_key && ev.company_name ? { key: ev.company_key, name: ev.company_name } : null,
    firstSeen: visibleFirstSeen(ev, notices),
    noticeCount: notices.length,
    counts: breachCounts(notices),
    jurisdictions: [
      ...new Set(
        notices.flatMap(({ row, mode }) => (mode === 'full' && row.jurisdiction ? [row.jurisdiction] : [])),
      ),
    ].sort(),
    sources: [...new Set(notices.map((n) => n.row.source))].sort(),
  };
  const dates = visibleDates(notices);
  if (dates) out.dates = dates;
  return out;
}

const modeOf = (v: Visible, source: string): 'full' | 'link' | null =>
  v.full.includes(source) ? 'full' : v.link.includes(source) ? 'link' : null;

/** Visible notices only, each with its display mode. Hidden-source rows are never selected. */
function visibleNotices(rows: NoticeRow[], v: Visible) {
  return rows.flatMap((row) => {
    const mode = modeOf(v, row.source);
    return mode ? [{ row, mode }] : [];
  });
}

export async function listBreaches(
  env: WorldEnv,
  v: Visible,
  q: string | undefined,
  page: number,
): Promise<{ items: BreachSummary[]; next: number | null; credits: ReturnType<typeof creditsFor> }> {
  const ids = allVisible(v);
  if (ids.length === 0) return { items: [], next: null, credits: [] };
  const offset = (page - 1) * PAGE_SIZE;
  // ?1 limit, ?2 offset, ?3 like pattern (or unused), ?4… sources
  const base = q === undefined ? 3 : 4;
  const src = placeholders(base, ids.length);
  const match =
    q === undefined
      ? ''
      : `AND (c.name LIKE ?3 ESCAPE '\\' OR EXISTS (SELECT 1 FROM breach_notices m WHERE m.company_key = e.company_key AND m.event_key = e.key AND m.source IN (${src}) AND m.raw_name LIKE ?3 ESCAPE '\\'))`;
  const binds: (string | number)[] = [PAGE_SIZE + 1, offset];
  if (q !== undefined) binds.push(likePattern(q));
  binds.push(...ids, ...v.full);
  const fullSrc = placeholders(base + ids.length, v.full.length);
  // The event row is built from every notice, so its first_seen is not used for order: sort on visible notices only.
  const seen = `COALESCE(
      (SELECT MIN(s.notified) FROM breach_notices s WHERE s.company_key = e.company_key AND s.event_key = e.key AND s.source IN (${src})),
      (SELECT MIN(COALESCE(s.occurred_from, s.discovered)) FROM breach_notices s WHERE s.company_key = e.company_key AND s.event_key = e.key AND s.source IN (${fullSrc})),
      e.first_seen)`;
  const sql = `SELECT e.key AS key, e.company_key AS company_key, e.first_seen AS first_seen, e.dates AS dates, c.name AS company_name
    FROM breach_events e LEFT JOIN companies c ON c.key = e.company_key
    WHERE EXISTS (SELECT 1 FROM breach_notices n WHERE n.company_key = e.company_key AND n.event_key = e.key AND n.source IN (${src}))
    ${match}
    ORDER BY ${seen} DESC, e.key DESC LIMIT ?1 OFFSET ?2`;
  const rows =
    (
      await env.DB_WORLD.prepare(sql)
        .bind(...binds)
        .all<EventRow>()
    ).results ?? [];
  const next = rows.length > PAGE_SIZE ? page + 1 : null;
  const events = rows.slice(0, PAGE_SIZE);
  if (events.length === 0) return { items: [], next, credits: [] };

  const companies = [...new Set(events.flatMap((e) => (e.company_key ? [e.company_key] : [])))];
  const nsql = `SELECT source, notice_id, company_key, raw_name, occurred_from, occurred_to, discovered, notified, count, count_unit, jurisdiction, data_types, url, event_key
    FROM breach_notices WHERE company_key IN (${placeholders(1, companies.length)}) AND source IN (${placeholders(1 + companies.length, ids.length)})`;
  const noticeRows =
    (
      await env.DB_WORLD.prepare(nsql)
        .bind(...companies, ...ids)
        .all<NoticeRow>()
    ).results ?? [];
  const visible = visibleNotices(noticeRows, v);
  const items = events.map((ev) =>
    summarise(
      ev,
      visible.filter((n) => n.row.company_key === ev.company_key && n.row.event_key === ev.key),
    ),
  );
  const display = await displayFor(env.SETTINGS, ids);
  return {
    items,
    next,
    credits: creditsFor(
      items.flatMap((i) => i.sources),
      display,
    ),
  };
}

export async function breachDetail(env: WorldEnv, v: Visible, key: string): Promise<BreachDetail | null> {
  const ids = allVisible(v);
  if (ids.length === 0) return null;
  const ev = await env.DB_WORLD.prepare(
    `SELECT e.key AS key, e.company_key AS company_key, e.first_seen AS first_seen, e.dates AS dates, c.name AS company_name
     FROM breach_events e LEFT JOIN companies c ON c.key = e.company_key WHERE e.key = ?1`,
  )
    .bind(key)
    .first<EventRow>();
  if (!ev || !ev.company_key) return null;
  const rows =
    (
      await env.DB_WORLD.prepare(
        `SELECT source, notice_id, company_key, raw_name, occurred_from, occurred_to, discovered, notified, count, count_unit, jurisdiction, data_types, url, event_key
         FROM breach_notices WHERE company_key = ?1 AND event_key = ?2 AND source IN (${placeholders(3, ids.length)})`,
      )
        .bind(ev.company_key, key, ...ids)
        .all<NoticeRow>()
    ).results ?? [];
  const visible = visibleNotices(rows, v);
  if (visible.length === 0) return null;
  const summary = summarise(ev, visible);
  const notices = visible
    .map((n) => toNotice(n.row, n.mode))
    .sort(
      (a, b) =>
        cmp(a.notified ?? '', b.notified ?? '') || cmp(a.source, b.source) || cmp(a.noticeId, b.noticeId),
    );
  const display = await displayFor(env.SETTINGS, summary.sources);
  return { ...summary, notices, credits: creditsFor(summary.sources, display) };
}
