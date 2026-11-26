import { isCve } from '@ti/core/ids';
import type { InboxRow } from '@ti/core/inbox';
import { vulnDocKey } from '@ti/core/r2-keys';
import type {
  AdvisoryRecord,
  IncidentRecord,
  NoticeRecord,
  ParsedRecord,
  SignalRecord,
  TechniqueRecord,
  VulnRecord,
} from '@ti/core/types';
import { affectedRows, type PackagePlan, packageWrites } from './affected';
import { linkNotices, noticeOut } from './breach';
import { noticeChange, vulnChanges } from './changes';
import { differs, isoDate, text } from './clean';
import { isHot } from './detect';
import { attach, baseFromStored, baseFromSummary, emptyVulnRow, mergeVulnRows, newDraft } from './draft';
import { candidateIds, type HubRecord, resolveHubs } from './hubs';
import { recordKind } from './kinds';
import { advisoryRow, aliasRow } from './map/advisory';
import { incidentRow } from './map/incident';
import { applySignal, signalRow } from './map/signal';
import { techniqueRow } from './map/technique';
import { applyVuln } from './map/vuln';
import {
  ADVISORY_STATUSES,
  ALIAS_SOURCE,
  fullRow,
  INCIDENT_KINDS,
  KEV_SOURCE,
  type LinkTable,
  pkOf,
  ROW_ORDER,
  type Row,
  SIGNAL_KINDS,
} from './tables';

export interface LinkDeps {
  /**
   * Current rows for these keys, for alias lookups and change detection. Each key is an object of the
   * columns of one index (the primary key, or `name_key` / `company_key` on `breach_notices`), using the
   * real column names; all keys in one call share the same columns. The linker calls this at most once
   * per table per link(), except `breach_notices`: at most three times (by primary key, by `name_key`,
   * by `company_key`). The implementation splits the keys into as many queries as D1's bound-parameter
   * limit needs. `package_advisories` is read by `source, source_id`, and `affected` by its record index
   * (`source, source_id`); each at most once per link().
   */
  read(table: string, keys: Record<string, unknown>[]): Promise<Record<string, unknown>[]>;
  /**
   * Cold-vulnerability summary from lookup/vuln/<shard>.json, used to promote a cold flaw: a row shaped
   * like a `vulns` row (same column names). Null if none.
   */
  lookupCold(vulnKey: string): Promise<Record<string, unknown> | null>;
  now(): Date;
  newId(): string;
}

export interface LinkResult {
  /**
   * Every D1 write, including `changes` rows. Hot-set entities only, except package rows
   * (`affected`, `package_advisories`), which are included for every advisory record, hot or cold.
   */
  rows: InboxRow[];
  /** Vulnerability keys whose docs/vuln/<key>.json must be rebuilt. */
  docs: string[];
  /** Cold records left out of D1 (they reach lake/ through the nightly fold). */
  skipped: number;
}

export interface Item<T> {
  idx: number;
  r: T;
}
interface HubItem {
  idx: number;
  kind: 'vuln' | 'advisory' | 'signal';
  r: HubRecord;
  ids: string[];
}

const unique = <T>(xs: Iterable<T>): T[] => [...new Set(xs)];
const isPromoting = (r: HubRecord, kind: HubItem['kind']): boolean =>
  kind === 'signal' &&
  (((r as SignalRecord).kind === 'exploited_wild' && r.source === KEV_SOURCE) ||
    (r as SignalRecord).kind === 'public_exploit');

/**
 * Turns parsed records into hot-set rows, aliases and change rows. Pure: no I/O except through `deps`.
 * Order: classify, read (advisories + world, vulns, signals), resolve hubs, promote, fold, build rows.
 */
export async function link(records: ParsedRecord[], deps: LinkDeps): Promise<LinkResult> {
  if (records.length === 0) return { rows: [], docs: [], skipped: 0 };
  const kinds = records.map(recordKind); // throws on an unrecognised record, before any read
  const nowDate = deps.now();
  const at = nowDate.toISOString();
  let skipped = 0;

  // 1. Classify and drop what cannot be keyed safely.
  const hubItems: HubItem[] = [];
  const notices: Item<NoticeRecord>[] = [];
  const incidents: Item<IncidentRecord>[] = [];
  const techniques: Item<TechniqueRecord>[] = [];
  records.forEach((rec, idx) => {
    const kind = kinds[idx];
    if (kind === 'notice') {
      const r = rec as NoticeRecord;
      if (text(r.source) && text(r.noticeId) && text(r.rawName) && text(r.countUnit))
        notices.push({ idx, r });
      else skipped++;
    } else if (kind === 'incident') {
      const r = rec as IncidentRecord;
      if (text(r.source) && text(r.incidentId) && text(r.title) && INCIDENT_KINDS.includes(r.kind))
        incidents.push({ idx, r });
      else skipped++;
    } else if (kind === 'technique') {
      const r = rec as TechniqueRecord;
      if (text(r.id) && text(r.framework) && text(r.name)) techniques.push({ idx, r });
      else skipped++;
    } else {
      const r = rec as HubRecord;
      const source = text(r.source);
      let ok = !!source && source !== ALIAS_SOURCE;
      if (kind === 'advisory') ok &&= ADVISORY_STATUSES.includes((r as AdvisoryRecord).status);
      if (kind === 'signal') {
        const s = r as SignalRecord;
        ok &&= SIGNAL_KINDS.includes(s.kind) && !!text(s.ref) && isoDate(s.firstSeen) !== null;
      }
      const ids = ok ? candidateIds(r) : null;
      if (ids) hubItems.push({ idx, kind: kind as HubItem['kind'], r, ids });
      else skipped++;
    }
  });

  // 2. Reads, each table at most once, never with an empty key list.
  const read = async (table: LinkTable, keys: Row[]): Promise<Row[]> =>
    keys.length === 0 ? [] : deps.read(table, keys);
  const index = (table: LinkTable, rows: Row[]): Map<string, Row> =>
    new Map(rows.map((row) => [pkOf(table, row), row]));

  const advKeys: Row[] = [];
  const aliasIds = new Set<string>();
  for (const it of hubItems) {
    if (it.kind === 'advisory') {
      const a = it.r as AdvisoryRecord;
      advKeys.push({ source: a.source, source_id: it.ids[0] });
    }
    for (const id of it.ids) if (!isCve(id)) aliasIds.add(id);
  }
  for (const id of aliasIds) advKeys.push({ source: ALIAS_SOURCE, source_id: id });
  const dedupe = (table: LinkTable, keys: Row[]): Row[] => [
    ...new Map(keys.map((k) => [pkOf(table, k), k])).values(),
  ];

  const [advRows, techRows, noticeRows, incidentRows] = await Promise.all([
    read('advisories', dedupe('advisories', advKeys)),
    read(
      'techniques',
      dedupe(
        'techniques',
        techniques.map((t) => ({ id: t.r.id })),
      ),
    ),
    read(
      'breach_notices',
      dedupe(
        'breach_notices',
        notices.map((n) => ({ source: n.r.source, notice_id: n.r.noticeId })),
      ),
    ),
    read(
      'incidents',
      dedupe(
        'incidents',
        incidents.map((i) => ({ source: i.r.source, incident_id: i.r.incidentId })),
      ),
    ),
  ]);
  const advStored = index('advisories', advRows);
  const techStored = index('techniques', techRows);
  const noticeStored = index('breach_notices', noticeRows);
  const incidentStored = index('incidents', incidentRows);

  const storedAliases = new Map<string, string>();
  for (const row of advRows) {
    if (row.source === ALIAS_SOURCE && typeof row.source_id === 'string' && typeof row.vuln_key === 'string')
      storedAliases.set(row.source_id, row.vuln_key);
  }

  const vulnKeys = unique([...hubItems.flatMap((it) => it.ids), ...storedAliases.values()]);
  const vulnRows = index(
    'vulns',
    await read(
      'vulns',
      vulnKeys.map((key) => ({ key })),
    ),
  );
  const vulnStored = (key: string): Row | undefined => vulnRows.get(pkOf('vulns', { key }));
  const storedVulnKeys = new Set(vulnKeys.filter((k) => vulnStored(k)));

  // 3. Hubs.
  const hubs = resolveHubs(
    hubItems.map((it) => it.r),
    storedAliases,
    storedVulnKeys,
  ) as string[];
  const groups = new Map<string, HubItem[]>();
  hubItems.forEach((it, i) => {
    const hub = hubs[i] as string;
    const g = groups.get(hub);
    if (g) g.push(it);
    else groups.set(hub, [it]);
  });

  const signalKeys = dedupe(
    'signals',
    hubItems.flatMap((it, i) => {
      if (it.kind !== 'signal') return [];
      const s = it.r as SignalRecord;
      return [{ vuln_key: hubs[i], kind: s.kind, source: s.source, ref: s.ref }];
    }),
  );
  const signalStored = index('signals', await read('signals', signalKeys));

  // 4. Fold each hub.
  const buckets: Record<LinkTable, { idx: number; row: InboxRow }[]> = {
    vulns: [],
    advisories: [],
    signals: [],
    techniques: [],
    companies: [],
    breach_events: [],
    breach_notices: [],
    incidents: [],
    changes: [],
  };
  const vulnDeletes: InboxRow[] = [];
  const docHubs = new Set<string>();
  const upsert = (table: LinkTable, idx: number, row: Row, hub?: string) => {
    buckets[table].push({ idx, row: { table, op: 'upsert', row: fullRow(table, row) } });
    if (hub) docHubs.add(hub);
  };
  const mergeClaims = new Set<string>();
  const aliasClaims = new Set<string>();

  for (const [hub, items] of groups) {
    const idx0 = (items[0] as HubItem).idx;
    const stored = vulnStored(hub);
    const named = unique(items.flatMap((it) => it.ids)).filter(
      (id) => !isCve(id) && id !== hub && !groups.has(id),
    );
    const merging = named.filter((id) => vulnStored(id) && !mergeClaims.has(id));

    let base: Row | null = null;
    let fromD1 = false;
    if (stored || merging.length > 0) {
      fromD1 = true;
      base = stored ? baseFromStored(hub, stored) : emptyVulnRow(hub);
      for (const id of merging) base = mergeVulnRows(base, baseFromStored(id, vulnStored(id) as Row));
    }
    const promoted = !fromD1 && items.some((it) => isPromoting(it.r, it.kind));
    if (promoted) {
      const summary = await deps.lookupCold(hub);
      base = summary ? baseFromSummary(hub, summary) : null;
    }
    const d = newDraft(hub, base);
    d.fromD1 = fromD1;
    d.promoted = promoted;
    if (promoted) d.before ??= { key: hub };

    const advOut = new Map<string, Row>();
    const sigOut = new Map<string, Row>();
    for (const it of items)
      if (it.kind === 'vuln') {
        applyVuln(d, it.r as VulnRecord);
        attach(d, it.r.source);
      }
    for (const it of items)
      if (it.kind === 'advisory') {
        const a = it.r as AdvisoryRecord;
        const pk = pkOf('advisories', { source: a.source, source_id: it.ids[0] });
        const prior = advStored.get(pk);
        advOut.set(pk, advisoryRow(hub, a, prior));
        if (
          !prior &&
          d.fixSource === null &&
          a.source !== 'cve-list' &&
          a.affected?.some((x) => text(x?.fixed))
        )
          d.fixSource = a.source;
        attach(d, a.source);
      }
    for (const it of items)
      if (it.kind === 'signal') {
        const s = it.r as SignalRecord;
        const row = signalRow(hub, s);
        const pk = pkOf('signals', row);
        const have = sigOut.get(pk);
        if (!signalStored.has(pk) && (!have || s.firstSeen < (have.first_seen as string)))
          sigOut.set(pk, row);
        applySignal(d, s);
        attach(d, s.source);
      }

    const hot =
      fromD1 ||
      promoted ||
      isHot({
        published: d.row.published as string | null,
        kevAdded: d.row.kev_added as string | null,
        exploitPublic: d.row.exploit_public === 1,
        epss: d.row.epss as number | null,
      });
    if (!hot) {
      skipped += d.attached;
      continue;
    }

    // Claim merges and aliases only for a hot hub; the first hub to name an ID keeps it.
    for (const id of merging) {
      mergeClaims.add(id);
      vulnDeletes.push({ table: 'vulns', op: 'delete', row: { key: id } });
      docHubs.add(hub);
    }
    d.row.hot = 1;
    d.row.doc_key = vulnDocKey(hub);
    d.row.modified = stored?.modified ?? '';
    if (differs(d.row, stored)) upsert('vulns', idx0, { ...d.row, modified: at }, hub);

    for (const it of items) {
      if (it.kind !== 'advisory') continue;
      const a = it.r as AdvisoryRecord;
      const pk = pkOf('advisories', { source: a.source, source_id: it.ids[0] });
      const row = advOut.get(pk);
      if (!row) continue;
      advOut.delete(pk);
      if (differs(row, advStored.get(pk))) upsert('advisories', it.idx, { ...row, modified: at }, hub);
    }
    for (const id of named) {
      if (aliasClaims.has(id)) continue;
      aliasClaims.add(id);
      const prior = advStored.get(pkOf('advisories', { source: ALIAS_SOURCE, source_id: id }));
      if (prior?.vuln_key === hub) continue;
      const idx = items.find((it) => it.ids.includes(id))?.idx ?? idx0;
      upsert('advisories', idx, aliasRow(id, hub, at, prior), hub);
    }
    for (const it of items) {
      if (it.kind !== 'signal') continue;
      const s = it.r as SignalRecord;
      const pk = pkOf('signals', { vuln_key: hub, kind: s.kind, source: s.source, ref: s.ref });
      const row = sigOut.get(pk);
      if (!row) continue;
      sigOut.delete(pk);
      upsert('signals', it.idx, row, hub);
    }
    for (const c of vulnChanges(d, at, deps.newId)) upsert('changes', idx0, c, hub);
  }

  // 5. World records: always hot, first record per key wins.
  const seen = new Set<string>();
  const matched = await linkNotices(notices, deps, at, noticeStored);
  const firstIdx = (pick: (l: (typeof matched.notices)[number]) => string | null): Map<string, number> => {
    const m = new Map<string, number>();
    for (const l of matched.notices) {
      const key = pick(l);
      if (key !== null && !m.has(key)) m.set(key, l.idx);
    }
    return m;
  };
  const companyIdx = firstIdx((l) => l.companyKey);
  const eventIdx = firstIdx((l) => l.eventKey);
  for (const row of matched.companies) upsert('companies', companyIdx.get(row.key as string) ?? 0, row);
  for (const row of matched.events) upsert('breach_events', eventIdx.get(row.key as string) ?? 0, row);
  for (const l of matched.notices) {
    const out = noticeOut(l, at);
    if (out.changed) upsert('breach_notices', l.idx, out.row);
    const change = noticeChange({ ...l.r, companyKey: l.companyKey ?? undefined }, l.stored, at, deps.newId);
    if (change) upsert('changes', l.idx, change);
  }
  for (const { idx, r } of incidents) {
    const pk = pkOf('incidents', { source: r.source, incident_id: r.incidentId });
    if (seen.has(`i${pk}`)) continue;
    seen.add(`i${pk}`);
    const row = incidentRow(r, incidentStored.get(pk), at);
    if (row) upsert('incidents', idx, row);
  }
  for (const { idx, r } of techniques) {
    const pk = pkOf('techniques', { id: r.id });
    if (seen.has(`t${pk}`)) continue;
    seen.add(`t${pk}`);
    const row = techniqueRow(r, techStored.get(pk));
    if (row) upsert('techniques', idx, row);
  }

  const packageRows = await packageRowsOf(hubItems, deps);

  const rows: InboxRow[] = [];
  for (const table of ROW_ORDER) {
    if (table === 'changes') rows.push(...packageRows);
    if (table === 'vulns') rows.push(...vulnDeletes);
    rows.push(...buckets[table].sort((a, b) => a.idx - b.idx).map((b) => b.row)); // stable
  }
  return { rows, docs: [...docHubs].sort(), skipped };
}

/** Package rows for the newest copy of each advisory record in this call, hot or cold. */
async function packageRowsOf(hubItems: HubItem[], deps: LinkDeps): Promise<InboxRow[]> {
  const latest = new Map<string, HubItem>();
  for (const it of hubItems) {
    if (it.kind !== 'advisory') continue;
    const a = it.r as AdvisoryRecord;
    const k = JSON.stringify([a.source, it.ids[0]]);
    const have = latest.get(k);
    if (!have || String(a.modified ?? '') >= String((have.r as AdvisoryRecord).modified ?? ''))
      latest.set(k, it);
  }
  const planned: { it: HubItem; plan: PackagePlan }[] = [];
  for (const it of latest.values()) {
    const a = it.r as AdvisoryRecord;
    const plan = affectedRows(a);
    if (typeof plan.advisory.source_id !== 'string') continue;
    if (plan.names > 0 || a.status !== 'active') planned.push({ it, plan });
  }
  if (planned.length === 0) return [];
  planned.sort((x, y) => x.it.idx - y.it.idx);
  const keys = planned.map(({ plan }) => ({
    source: plan.advisory.source,
    source_id: plan.advisory.source_id,
  }));
  const [advRows, rangeRows] = await Promise.all([
    deps.read('package_advisories', keys),
    deps.read('affected', keys),
  ]);
  const advBy = new Map(advRows.map((row) => [JSON.stringify([row.source, row.source_id]), row]));
  const rangesBy = new Map<string, Row[]>();
  for (const row of rangeRows) {
    const k = JSON.stringify([row.source, row.source_id]);
    const list = rangesBy.get(k);
    if (list) list.push(row);
    else rangesBy.set(k, [row]);
  }
  const out: InboxRow[] = [];
  for (const { it, plan } of planned) {
    const k = JSON.stringify([plan.advisory.source, plan.advisory.source_id]);
    out.push(
      ...packageWrites(it.r as AdvisoryRecord, plan, {
        advisory: advBy.get(k),
        ranges: rangesBy.get(k) ?? [],
      }),
    );
  }
  return out;
}
