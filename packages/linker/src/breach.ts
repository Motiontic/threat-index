import type { NoticeRecord } from '@ti/core/types';
import { differs, isoDate, text } from './clean';
import {
  type CompanyKey,
  companyRow,
  hintKey,
  incidentSpan,
  jurisdictionCode,
  nameKey,
  normaliseName,
  type Span,
  spansClose,
} from './company';
import type { Item, LinkDeps } from './link';
import { noticeRow } from './map/notice';
import { type LinkTable, pkOf, type Row } from './tables';

export interface LinkedNotice {
  idx: number;
  r: NoticeRecord;
  /** The stored row, when this notice was linked before. */
  stored?: Row;
  /** Null when the name normalises to nothing: no company, no event. */
  companyKey: string | null;
  /** `normaliseName(rawName)`, written to `breach_notices.name_key`. */
  nameKey: string;
  confidence: number;
  eventKey: string | null;
}

const CLOSE_DAYS = 30;
const KEY_MAX = 199;
const isHinted = (key: string | null | undefined): key is string =>
  !!key && (key.startsWith('cik:') || key.startsWith('domain:'));
/** What a stored notice counts for: a hint key was matched for certain, a name key was not. */
const storedConfidence = (key: unknown): number => (isHinted(key as string) ? 1 : 0.6);

const rowSpan = (row: Row): Span | null =>
  incidentSpan({
    occurredFrom: row.occurred_from,
    occurredTo: row.occurred_to,
    discovered: row.discovered,
    notified: row.notified,
  });

interface Member {
  span: Span | null;
}
interface Ev {
  company: string;
  members: Member[];
}

/**
 * Fills `eventKey` of every new notice that has a company. `prior` is the stored notices of those
 * companies. A new notice joins the event of its company that has a notice with a span within 30 days of
 * its own (the one whose earliest notice is earliest); events are never merged. Otherwise it starts one.
 */
export function assignEvents(linked: LinkedNotice[], prior: Row[]): void {
  const events = new Map<string, Ev>();
  const counted = new Set<string>();
  const join = (key: string, company: string, span: Span | null) => {
    const ev = events.get(key);
    if (ev) ev.members.push({ span });
    else events.set(key, { company, members: [{ span }] });
  };
  const addStored = (row: Row) => {
    const pk = pkOf('breach_notices', row);
    if (counted.has(pk)) return;
    counted.add(pk);
    if (text(row.event_key) && text(row.company_key))
      join(row.event_key as string, row.company_key as string, rowSpan(row));
  };
  for (const row of prior) addStored(row);
  for (const l of linked) if (l.stored) addStored(l.stored);

  for (const l of linked) {
    if (l.stored) {
      l.eventKey = text(l.stored.event_key) ? (l.stored.event_key as string) : null;
      continue;
    }
    if (!l.companyKey) {
      l.eventKey = null;
      continue;
    }
    const span = incidentSpan(l.r);
    let best: { key: string; earliest: string } | null = null;
    if (span)
      for (const [key, ev] of events) {
        if (ev.company !== l.companyKey) continue;
        if (!ev.members.some((m) => m.span && spansClose(m.span, span, CLOSE_DAYS))) continue;
        const earliest = ev.members.reduce(
          (e, m) => (m.span && m.span.from < e ? m.span.from : e),
          '9999-99-99',
        );
        if (!best || earliest < best.earliest || (earliest === best.earliest && key < best.key))
          best = { key, earliest };
      }
    if (best) {
      l.eventKey = best.key;
      join(best.key, l.companyKey, span);
      continue;
    }
    // The key is cut so that it, and a numeric suffix, stay under 200 characters.
    const base = (
      span ? `${l.companyKey}@${span.from}` : `${l.companyKey}@${l.r.source}:${l.r.noticeId}`
    ).slice(0, KEY_MAX - 10);
    let key = base;
    for (let n = 2; events.has(key); n++) key = `${base}-${n}`;
    l.eventKey = key;
    join(key, l.companyKey, span);
  }
}

/**
 * The `breach_events` row rebuilt from all of the event's notice rows. No total is ever computed: counts
 * stay under their unit and jurisdiction, and the largest count seen for each is kept. A row may carry a
 * non-column `confidence` (a notice matched by name this batch); stored rows derive it from `company_key`.
 */
export function eventRow(key: string, notices: Row[], stored: Row | undefined, at: string): Row | null {
  let from: string | null = null;
  let to: string | null = null;
  let notified: string | null = null;
  let confidence = 1;
  const counts = new Map<string, Map<string, number>>();
  for (const n of notices) {
    const span = rowSpan(n);
    if (span) {
      if (from === null || span.from < from) from = span.from;
      if (to === null || span.to > to) to = span.to;
    }
    const nd = isoDate(n.notified)?.slice(0, 10);
    if (nd && (notified === null || nd < notified)) notified = nd;
    confidence = Math.min(
      confidence,
      typeof n.confidence === 'number' ? n.confidence : storedConfidence(n.company_key),
    );
    if (typeof n.count === 'number' && typeof n.count_unit === 'string') {
      const byJuris = counts.get(n.count_unit) ?? new Map<string, number>();
      counts.set(n.count_unit, byJuris);
      const juris = text(n.jurisdiction)?.trim() ?? '-';
      byJuris.set(juris, Math.max(byJuris.get(juris) ?? 0, n.count));
    }
  }
  // Object.fromEntries defines own properties, so a jurisdiction named `__proto__` stays data.
  const byUnit = Object.fromEntries(
    [...counts]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([unit, m]) => [unit, Object.fromEntries([...m].sort(([a], [b]) => (a < b ? -1 : 1)))]),
  );
  const row: Row = {
    key,
    company_key: notices.map((n) => text(n.company_key)).find((k) => k !== null) ?? null,
    first_seen: notified ?? at.slice(0, 10),
    dates: from && to ? JSON.stringify({ from, to }) : null,
    counts_by_unit: JSON.stringify(byUnit),
    notice_count: notices.length,
    confidence,
    modified: stored?.modified ?? '',
  };
  return differs(row, stored) ? { ...row, modified: at } : null;
}

/**
 * The notice's final `breach_notices` row: `noticeRow` for the resolved company, plus `name_key` and
 * `event_key`. `row` is the stored row when nothing but `modified` would change.
 */
export function noticeOut(l: LinkedNotice, at: string): { row: Row; changed: boolean } {
  const base = noticeRow({ ...l.r, companyKey: l.companyKey ?? undefined }, l.stored, at);
  const row: Row = {
    ...(base ?? (l.stored as Row)),
    name_key: l.nameKey === '' ? null : l.nameKey,
    event_key: l.eventKey,
  };
  if (!differs(row, l.stored)) return { row: l.stored as Row, changed: false };
  return { row: { ...row, modified: at }, changed: true };
}

const unique = <T>(xs: Iterable<T>): T[] => [...new Set(xs)];

/**
 * Matches each notice to a company (CIK hint, domain hint, then name within 30 days of an earlier hinted
 * notice), groups new notices into events, and builds the `companies` and `breach_events` rows. A stored
 * notice keeps its company and event. Reads: `breach_notices` by `name_key` and by `company_key`,
 * `companies`, `breach_events`; each only when it has keys.
 */
export async function linkNotices(
  notices: Item<NoticeRecord>[],
  deps: LinkDeps,
  at: string,
  stored: Map<string, Row>,
): Promise<{ companies: Row[]; events: Row[]; notices: LinkedNotice[] }> {
  const read = async (table: LinkTable, keys: Row[]): Promise<Row[]> =>
    keys.length === 0 ? [] : deps.read(table, keys);

  const seen = new Set<string>();
  const linked: LinkedNotice[] = [];
  for (const { idx, r } of notices) {
    const pk = pkOf('breach_notices', { source: r.source, notice_id: r.noticeId });
    if (seen.has(pk)) continue; // first record per key wins
    seen.add(pk);
    const prior = stored.get(pk);
    linked.push({
      idx,
      r,
      stored: prior,
      companyKey: prior ? (text(prior.company_key) ?? null) : null,
      nameKey: normaliseName(r.rawName),
      confidence: prior ? storedConfidence(prior.company_key) : 0,
      eventKey: null,
    });
  }

  // Earlier notices by name: stored ones from D1, then the batch as it is resolved.
  const byName = await read(
    'breach_notices',
    unique(linked.filter((l) => !l.stored && l.nameKey !== '').map((l) => l.nameKey)).map((name_key) => ({
      name_key,
    })),
  );
  interface Candidate {
    key: string;
    span: Span;
  }
  const pool = new Map<string, Map<string, Candidate>>();
  const poolAdd = (name: string, pk: string, key: unknown, span: Span | null) => {
    if (!isHinted(key as string) || !span) return;
    const m = pool.get(name) ?? new Map<string, Candidate>();
    pool.set(name, m);
    if (!m.has(pk)) m.set(pk, { key: key as string, span });
  };
  for (const row of byName)
    poolAdd(String(row.name_key), pkOf('breach_notices', row), row.company_key, rowSpan(row));
  for (const l of linked)
    if (l.stored) poolAdd(l.nameKey, pkOf('breach_notices', l.stored), l.companyKey, rowSpan(l.stored));

  for (const l of linked) {
    if (l.stored || l.nameKey === '') continue;
    const pk = pkOf('breach_notices', { source: l.r.source, notice_id: l.r.noticeId });
    const span = incidentSpan(l.r);
    const hint = hintKey(l.r.companyKey);
    if (hint) {
      l.companyKey = hint.key;
      l.confidence = 1;
    } else {
      let best: Candidate | null = null;
      if (span)
        for (const c of pool.get(l.nameKey)?.values() ?? []) {
          if (!spansClose(c.span, span, CLOSE_DAYS)) continue;
          const rank = (x: Candidate) => (x.key.startsWith('cik:') ? 0 : 1);
          if (!best || rank(c) < rank(best) || (rank(c) === rank(best) && c.span.from < best.span.from))
            best = c;
        }
      if (best) {
        l.companyKey = best.key;
        l.confidence = 0.8;
      } else {
        l.companyKey = nameKey(l.nameKey, jurisdictionCode(l.r.jurisdiction));
        l.confidence = 0.6;
      }
    }
    poolAdd(l.nameKey, pk, l.companyKey, span);
  }

  const companyKeys = unique(linked.flatMap((l) => (l.companyKey ? [l.companyKey] : [])));
  const companyStored = new Map(
    (
      await read(
        'companies',
        companyKeys.map((key) => ({ key })),
      )
    ).map((row) => [row.key as string, row]),
  );
  const prior = await read(
    'breach_notices',
    companyKeys.map((company_key) => ({ company_key })),
  );
  const eventStored = new Map(
    (
      await read(
        'breach_events',
        unique(prior.flatMap((row) => (text(row.event_key) ? [row.event_key as string] : []))).map((key) => ({
          key,
        })),
      )
    ).map((row) => [row.key as string, row]),
  );

  assignEvents(linked, prior);

  // Companies: from the new notices only, with the hint carried by the key.
  const names = new Map<CompanyKey, string[]>();
  for (const l of linked)
    if (!l.stored && l.companyKey) names.set(l.companyKey, [...(names.get(l.companyKey) ?? []), l.r.rawName]);
  const companies: Row[] = [];
  for (const [key, rawNames] of names) {
    const row = companyRow(key, rawNames, companyStored.get(key), hintKey(key) ?? undefined);
    if (row) companies.push(row);
  }

  // Events: rebuilt from every notice of each event this batch touched.
  const rows = new Map<string, Row>(prior.map((row) => [pkOf('breach_notices', row), row]));
  const touched = new Set<string>();
  for (const l of linked) {
    const { row, changed } = noticeOut(l, at);
    const pk = pkOf('breach_notices', { source: l.r.source, notice_id: l.r.noticeId });
    rows.set(pk, l.stored ? row : { ...row, confidence: l.confidence });
    if (l.eventKey && (!l.stored || changed)) touched.add(l.eventKey);
  }
  const members = new Map<string, Row[]>();
  for (const row of rows.values()) {
    const key = text(row.event_key);
    if (!key || !touched.has(key)) continue;
    members.set(key, [...(members.get(key) ?? []), row]);
  }
  const events: Row[] = [];
  for (const [key, ns] of members) {
    const row = eventRow(key, ns, eventStored.get(key), at);
    if (row) events.push(row);
  }
  return { companies, events, notices: linked };
}
