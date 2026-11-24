// An in-process stand-in for ti-api's public routes, over the hand-written fixtures. It answers in exactly the
// `@ti/core/api` shapes, so the pages and the client run the same code against fixtures and the real API.

import type {
  Credit,
  EntryFull,
  EntryPreview,
  HomeChange,
  HomeItem,
  HomeResponse,
  IndexLetterResponse,
  SearchHit,
  SearchResponse,
  SourcesResponse,
} from '@ti/core/api';
import { normaliseId } from '@ti/core/ids';
import { NVD_NOTICE } from '@ti/core/licence';
import type {
  BreachDetail,
  BreachSummary,
  IncidentDetail,
  IncidentSummary,
  TechniqueDetail,
  TechniqueSummary,
  WorldList,
} from '@ti/core/world-api';
import { SOURCE_BY_ID, SOURCES } from '@ti/sources/registry';
import { fakeUserOf, fixtureAccountApi, fixtureFullEntry } from './fixture-account.server';
import world from './fixtures/world.json';
import { FIXTURE_ENTRIES, type FixtureEntry } from './fixtures.server';

export const PAGE_SIZE = 20;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const bad = (message: string) => json({ error: message }, 400);

/** The API's rule: each cited source's registry credit, and the NVD notice once whenever `nvd` is cited. */
export function fixtureCredits(sourceIds: string[]): Credit[] {
  const out: Credit[] = [];
  for (const id of sourceIds) {
    const s = SOURCE_BY_ID.get(id);
    out.push({ sourceId: id, name: s?.name ?? id, text: s?.credit ?? `Source: ${id}` });
  }
  if (sourceIds.includes('nvd') && !out.some((c) => c.text === NVD_NOTICE))
    out.push({ sourceId: 'nvd', name: 'NVD', text: NVD_NOTICE });
  return out;
}

/** CVEs are `cve`; everything else keeps its fixture type as the kind. */
function kindOf(e: FixtureEntry): string {
  return e.key.startsWith('CVE-') ? 'cve' : e.type;
}

function toPreview(e: FixtureEntry): EntryPreview {
  const out: EntryPreview = {
    key: e.key,
    kind: kindOf(e),
    title: e.title,
    summary: e.summary,
    aliases: [...e.aliases],
    exploited: e.kev_added !== null,
    credits: fixtureCredits(e.sources),
  };
  if (e.published) out.published = e.published;
  if (e.cvss !== null) out.cvss = e.cvss;
  if (e.kev_added) out.kevAdded = e.kev_added;
  return out;
}

function toHit(e: FixtureEntry): SearchHit & { kind: string } {
  const hit: SearchHit & { kind: string } = {
    key: e.key,
    kind: kindOf(e),
    title: e.title,
    summary: e.summary,
    exploited: e.kev_added !== null,
  };
  if (e.cvss !== null) hit.cvss = e.cvss;
  if (e.published) hit.published = e.published;
  return hit;
}

export function indexBucket(key: string): string {
  const first = key.charAt(0).toLowerCase();
  return first >= 'a' && first <= 'z' ? first : '0';
}

function byNewest(a: FixtureEntry, b: FixtureEntry): number {
  return (b.published ?? '').localeCompare(a.published ?? '') || a.key.localeCompare(b.key);
}

function severity(cvss: number | null): string | null {
  if (cvss === null) return null;
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  return 'low';
}

// An opaque cursor: base64url of the offset.
const encodeCursor = (offset: number) =>
  btoa(`o${offset}`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function decodeCursor(cursor: string | null): number | null {
  if (cursor === null) return 0;
  try {
    const text = atob(cursor.replace(/-/g, '+').replace(/_/g, '/'));
    const n = /^o(\d{1,6})$/.exec(text)?.[1];
    return n === undefined ? null : Number(n);
  } catch {
    return null;
  }
}

function page<T>(rows: T[], cursor: string | null): { rows: T[]; next?: string } | null {
  const offset = decodeCursor(cursor);
  if (offset === null) return null;
  const slice = rows.slice(offset, offset + PAGE_SIZE);
  return offset + PAGE_SIZE < rows.length
    ? { rows: slice, next: encodeCursor(offset + PAGE_SIZE) }
    : { rows: slice };
}

function search(url: URL): Response {
  const p = url.searchParams;
  const q = (p.get('q') ?? '').trim();
  if (q.length > 200) return bad('q is too long');
  const types = p.getAll('type');
  const sigs = p.getAll('sig');
  const sev = p.get('sev');
  const year = p.get('year');
  const sort = p.get('sort') ?? (q ? 'rel' : 'new');
  if (sort !== 'rel' && sort !== 'new') return bad('unknown sort');
  if (sev !== null && !['critical', 'high', 'medium', 'low'].includes(sev)) return bad('unknown sev');
  if (year !== null && !/^(19|20)\d{2}$/.test(year)) return bad('unknown year');
  if (sigs.some((s) => s !== 'kev')) return bad('unknown sig');
  if (types.some((t) => !['vuln', 'breach', 'ai', 'mal', 'tech', 'term'].includes(t)))
    return bad('unknown type');
  if (!q && types.length === 0 && sigs.length === 0 && !sev && !year)
    return bad('Add a word or an ID to search');

  const needle = q.toLowerCase();
  const normalised = normaliseId(q).toLowerCase();
  let rows = FIXTURE_ENTRIES.filter((e) => {
    if (types.length > 0 && !types.includes(e.type)) return false;
    if (sigs.includes('kev') && !e.kev_added) return false;
    if (sev && severity(e.cvss) !== sev) return false;
    if (year && !(e.published ?? '').startsWith(year)) return false;
    if (!needle) return true;
    return [e.key, ...e.aliases, e.title, e.subtitle, e.summary].some((f) =>
      f.toLowerCase().includes(needle),
    );
  });
  const exact = (e: FixtureEntry) =>
    needle !== '' && [e.key, ...e.aliases].some((k) => normaliseId(k).toLowerCase() === normalised);
  rows = [...rows].sort((a, b) =>
    sort === 'new' ? byNewest(a, b) : Number(exact(b)) - Number(exact(a)) || byNewest(a, b),
  );
  const paged = page(rows, p.get('cursor'));
  if (!paged) return bad('bad cursor');
  const body: SearchResponse = {
    query: q,
    hits: paged.rows.map(toHit),
    total: rows.length,
    credits: fixtureCredits([...new Set(paged.rows.flatMap((e) => e.sources))]),
  };
  if (paged.next) body.cursor = paged.next;
  return json(body);
}

function indexLetter(letter: string, url: URL): Response {
  if (!/^[a-z0]$/.test(letter)) return json({ error: 'Not found' }, 404);
  const rows = FIXTURE_ENTRIES.filter((e) => indexBucket(e.key) === letter).sort((a, b) =>
    a.key.localeCompare(b.key),
  );
  const paged = page(rows, url.searchParams.get('cursor'));
  if (!paged) return bad('bad cursor');
  const body: IndexLetterResponse = {
    letter,
    items: paged.rows.map((e) => ({ key: e.key, title: e.title })),
  };
  if (paged.next) body.cursor = paged.next;
  return json(body);
}

function sampleLastSuccess(index: number, cadence: string): string {
  const base = Date.UTC(2026, 10, 23, 9, 0, 0);
  const back: Record<string, number> = {
    '3h': 0,
    daily: 18,
    weekly: 24 * 4,
    monthly: 24 * 20,
    quarterly: 24 * 60,
  };
  return new Date(base - ((back[cadence] ?? 12) + (index % 3)) * 3_600_000).toISOString();
}

function sources(): Response {
  const body: SourcesResponse = {
    sources: SOURCES.map((s, i) => {
      const row: SourcesResponse['sources'][number] = {
        id: s.id,
        name: s.name,
        gives: s.gives,
        pattern: s.pattern,
        cadence: s.cadence,
        licence: s.licence,
        display: s.licence === 'wait' ? 'hidden' : s.licence === 'link' ? 'link' : 'full',
        credit: s.credit,
      };
      if (s.licence !== 'wait') {
        row.lastSuccess = sampleLastSuccess(i, s.cadence);
        row.lastRunStatus = 'ok';
      }
      return row;
    }),
  };
  return json(body);
}

// ---- the world routes: breaches, incidents, techniques ----

const WORLD_PAGE = 25;
const SOURCE_OF_FRAMEWORK: Record<string, string> = {
  attack: 'mitre-attack',
  atlas: 'mitre-atlas',
  cwe: 'cwe',
  capec: 'capec',
};
type FixtureBreach = Omit<BreachDetail, 'counts' | 'jurisdictions' | 'sources' | 'noticeCount' | 'credits'>;
type FixtureIncident = Omit<IncidentDetail, 'credits'>;
type FixtureTechnique = Omit<TechniqueDetail, 'children' | 'vulns' | 'vulnsMore' | 'credits'> & {
  vulns: string[];
};
const WORLD = world as unknown as {
  breaches: FixtureBreach[];
  incidents: FixtureIncident[];
  techniques: FixtureTechnique[];
};

/** The same rule as the API: one entry per (unit, jurisdiction), the largest count, never added. */
function fixtureBreach(b: FixtureBreach): BreachDetail {
  const best = new Map<string, BreachDetail['counts'][number]>();
  for (const n of b.notices) {
    if (n.display !== 'full' || n.count === undefined || !n.countUnit) continue;
    const k = `${n.countUnit}|${n.jurisdiction ?? ''}`;
    const cur = best.get(k);
    if (!cur || n.count > cur.count)
      best.set(k, { unit: n.countUnit, jurisdiction: n.jurisdiction ?? null, count: n.count });
  }
  const sources = [...new Set(b.notices.map((n) => n.source))].sort();
  return {
    ...b,
    noticeCount: b.notices.length,
    counts: [...best.values()].sort((x, y) => x.unit.localeCompare(y.unit)),
    jurisdictions: [
      ...new Set(b.notices.flatMap((n) => (n.display === 'full' && n.jurisdiction ? [n.jurisdiction] : []))),
    ].sort(),
    sources,
    credits: fixtureCredits(sources),
  };
}
const summaryOf = (d: BreachDetail): BreachSummary => {
  const { notices: _n, credits: _c, ...rest } = d;
  return rest;
};

function worldPage(url: URL): { q: string; page: number } | Response {
  const q = (url.searchParams.get('q') ?? '').trim().toLowerCase();
  if (q.length > 100) return bad('bad_query');
  const raw = url.searchParams.get('page');
  const page = raw === null ? 1 : /^\d{1,3}$/.test(raw) ? Number(raw) : 0;
  if (page < 1 || page > 40) return bad('bad_page');
  return { q, page };
}

function worldList<T>(rows: T[], page: number, sources: string[]): WorldList<T> {
  const slice = rows.slice((page - 1) * WORLD_PAGE, page * WORLD_PAGE);
  return {
    items: slice,
    page,
    next: rows.length > page * WORLD_PAGE ? page + 1 : null,
    credits: fixtureCredits([...new Set(sources)]),
  };
}

function breachesApi(url: URL, key: string | null): Response {
  const all = WORLD.breaches.map(fixtureBreach);
  if (key !== null) {
    const found = all.find((b) => b.key === key);
    return found ? json(found) : json({ error: 'not_found' }, 404);
  }
  const p = worldPage(url);
  if (p instanceof Response) return p;
  const rows = all
    .filter(
      (b) =>
        !p.q ||
        (b.company?.name ?? '').toLowerCase().includes(p.q) ||
        b.notices.some((n) => n.name.toLowerCase().includes(p.q)),
    )
    .sort((a, b) => b.firstSeen.localeCompare(a.firstSeen) || b.key.localeCompare(a.key));
  return json(
    worldList(
      rows.map(summaryOf),
      p.page,
      rows.flatMap((b) => b.sources),
    ),
  );
}

const INCIDENT_KINDS = ['ai', 'cyber_op', 'cyber_event'];
function incidentsApi(url: URL, source: string | null, id: string | null): Response {
  const withCredits = (i: FixtureIncident): IncidentDetail => ({ ...i, credits: fixtureCredits([i.source]) });
  if (source !== null && id !== null) {
    if (!SOURCE_BY_ID.has(source)) return bad('bad_id');
    const found = WORLD.incidents.find((i) => i.source === source && i.incidentId === id);
    return found ? json(withCredits(found)) : json({ error: 'not_found' }, 404);
  }
  const p = worldPage(url);
  if (p instanceof Response) return p;
  const kinds = new Set<string>();
  for (const k of url.searchParams.getAll('kind')) {
    if (k === 'cyber') {
      kinds.add('cyber_op');
      kinds.add('cyber_event');
    } else if (INCIDENT_KINDS.includes(k)) kinds.add(k);
    else return bad('bad_kind');
  }
  const rows = WORLD.incidents
    .filter((i) => (kinds.size === 0 || kinds.has(i.kind)) && (!p.q || i.title.toLowerCase().includes(p.q)))
    .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '') || a.incidentId.localeCompare(b.incidentId));
  const items: IncidentSummary[] = rows.map(
    ({ entities: _e, techniques: _t, ...summary }) => summary as IncidentSummary,
  );
  return json(
    worldList(
      items,
      p.page,
      rows.map((r) => r.source),
    ),
  );
}

function techniqueApi(url: URL, id: string | null): Response {
  const summary = (t: FixtureTechnique): TechniqueSummary => {
    const out: TechniqueSummary = { id: t.id, framework: t.framework, name: t.name };
    if (t.parent) out.parent = t.parent;
    return out;
  };
  if (id !== null) {
    if (!/^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?|CWE-\d{1,6}|CAPEC-\d{1,6})$/.test(id))
      return bad('bad_id');
    const t = WORLD.techniques.find((x) => x.id === id);
    if (!t) return json({ error: 'not_found' }, 404);
    const parent = WORLD.techniques.find((x) => x.id === t.parent);
    const detail: TechniqueDetail = {
      ...summary(t),
      children: WORLD.techniques.filter((x) => x.parent === t.id).map(summary),
      vulns: t.vulns.flatMap((k) => {
        const e = FIXTURE_ENTRIES.find((f) => f.key === k);
        if (!e) return [];
        const v: TechniqueDetail['vulns'][number] = {
          key: e.key,
          title: e.title,
          exploited: e.kev_added !== null,
        };
        if (e.cvss !== null) v.cvss = e.cvss;
        return [v];
      }),
      vulnsMore: false,
      credits: fixtureCredits([SOURCE_OF_FRAMEWORK[t.framework] ?? 'mitre-attack']),
    };
    if (t.summary) detail.summary = t.summary;
    if (parent) detail.parentRef = { id: parent.id, name: parent.name };
    return json(detail);
  }
  const p = worldPage(url);
  if (p instanceof Response) return p;
  const frameworks = url.searchParams.getAll('framework');
  if (frameworks.some((f) => !(f in SOURCE_OF_FRAMEWORK))) return bad('bad_framework');
  const rows = WORLD.techniques
    .filter(
      (t) =>
        (frameworks.length === 0 || frameworks.includes(t.framework)) &&
        (!p.q || t.id.toLowerCase().includes(p.q) || t.name.toLowerCase().includes(p.q)),
    )
    .sort((a, b) => a.framework.localeCompare(b.framework) || a.id.localeCompare(b.id));
  return json(
    worldList(
      rows.map(summary),
      p.page,
      rows.map((r) => SOURCE_OF_FRAMEWORK[r.framework] ?? 'mitre-attack'),
    ),
  );
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function dayMonth(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso);
  return m ? `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]}` : '';
}

/** The home route over the fixtures: the same shape and rules as ti-api's `/v1/home`, from the sample records. */
function home(): Response {
  const newest = (rows: FixtureEntry[], date: (e: FixtureEntry) => string) =>
    [...rows].sort((a, b) => date(b).localeCompare(date(a)) || a.key.localeCompare(b.key)).slice(0, 10);
  const vulns = FIXTURE_ENTRIES.filter((e) => e.type === 'vuln');
  const kev = vulns.filter((e) => e.kev_added);
  const mal = FIXTURE_ENTRIES.filter((e) => e.type === 'mal');
  const asItem = (e: FixtureEntry, date: string, signal?: string): HomeItem => {
    const item: HomeItem = { key: e.key, title: e.title, type: e.type === 'mal' ? 'mal' : 'vuln', date };
    if (signal) item.signal = signal;
    return item;
  };
  const breaches = WORLD.breaches
    .map(fixtureBreach)
    .sort((a, b) => b.firstSeen.localeCompare(a.firstSeen) || b.key.localeCompare(a.key));
  const incidents = [...WORLD.incidents].sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
  const ai = incidents.filter((i) => i.kind === 'ai');
  const changes: HomeChange[] = newest(kev, (e) => e.kev_added ?? '').map((e) => ({
    key: e.key,
    title: e.title,
    kind: 'newly_exploited',
    at: e.kev_added ?? '',
    source: 'cisa-kev',
    type: 'vuln',
  }));
  const body: HomeResponse = {
    counts: {
      vulnerabilities: vulns.length,
      exploited: kev.length,
      exploits: 0,
      breaches: breaches.length,
      aiIncidents: ai.length,
      cyberOperations: incidents.filter((i) => i.kind === 'cyber_op').length,
      maliciousPackages: mal.length,
      techniques: WORLD.techniques.length,
    },
    lists: {
      exploited: newest(kev, (e) => e.kev_added ?? '').map((e) =>
        asItem(e, e.kev_added ?? '', `CISA KEV ${dayMonth(e.kev_added ?? '')}`.trim()),
      ),
      vulnerabilities: newest(
        vulns.filter((e) => e.published),
        (e) => e.published ?? '',
      ).map((e) => asItem(e, e.published ?? '', e.cvss === null ? undefined : `CVSS ${e.cvss.toFixed(1)}`)),
      exploits: [],
      breaches: breaches.slice(0, 10).map((b) => {
        const item: HomeItem = {
          key: b.key,
          title: b.company?.name ?? b.key,
          type: 'breach',
          date: b.firstSeen,
          signal: `${b.noticeCount} ${b.noticeCount === 1 ? 'notice' : 'notices'}`,
        };
        return item;
      }),
      aiIncidents: ai.slice(0, 10).map((i) => {
        const item: HomeItem = {
          key: i.incidentId,
          source: i.source,
          title: i.title,
          type: 'ai',
          signal: SOURCE_BY_ID.get(i.source)?.name ?? i.source,
        };
        if (i.date) item.date = i.date;
        return item;
      }),
      maliciousPackages: newest(
        mal.filter((e) => e.published),
        (e) => e.published ?? '',
      ).map((e) => asItem(e, e.published ?? '')),
    },
    changes,
  };
  return json(body);
}

function decoded(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

function worldApi(url: URL, path: string): Response | null {
  const printable = (s: string | null): s is string => s !== null && /^[\x20-\x7e]{1,200}$/.test(s);
  if (path === '/v1/breaches') return breachesApi(url, null);
  const b = /^\/v1\/breaches\/([^/]+)$/.exec(path)?.[1];
  if (b !== undefined) {
    const key = decoded(b);
    return printable(key) ? breachesApi(url, key) : bad('bad_id');
  }
  if (path === '/v1/incidents') return incidentsApi(url, null, null);
  const i = /^\/v1\/incidents\/([^/]+)\/([^/]+)$/.exec(path);
  if (i) {
    const [s, id] = [decoded(i[1] as string), decoded(i[2] as string)];
    return s !== null && printable(id) ? incidentsApi(url, s, id) : bad('bad_id');
  }
  if (path === '/v1/techniques') return techniqueApi(url, null);
  const t = /^\/v1\/techniques\/([^/]+)$/.exec(path)?.[1];
  if (t !== undefined) {
    const id = decoded(t);
    return id === null ? bad('bad_id') : techniqueApi(url, id);
  }
  return null;
}

export async function fixtureApi(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === '/v1/me' || path.startsWith('/v1/me/') || path === '/v1/admin/ops')
    return fixtureAccountApi(request, path);
  if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
  if (path === '/v1/search') return search(url);
  if (path === '/v1/sources') return sources();
  if (path === '/v1/home') return home();
  const worldResponse = worldApi(url, path);
  if (worldResponse) return worldResponse;
  const entry = /^\/v1\/entries\/([^/]+)$/.exec(path)?.[1];
  if (entry !== undefined) {
    let id: string;
    try {
      id = decodeURIComponent(entry);
    } catch {
      return bad('bad id');
    }
    const wanted = normaliseId(id);
    const found = FIXTURE_ENTRIES.find(
      (e) => e.key === wanted || e.aliases.some((a) => normaliseId(a) === wanted),
    );
    if (!found) return json({ error: 'Not found' }, 404);
    // Only the fake bearer token gets the full view; the public client sends none.
    if (fakeUserOf(request)) {
      return json({ access: 'full', entry: fixtureFullEntry(found, { ...toPreview(found) } as EntryFull) });
    }
    return json({ access: 'preview', entry: toPreview(found) });
  }
  const letter = /^\/v1\/index\/([^/]+)$/.exec(path)?.[1];
  if (letter !== undefined) return indexLetter(decodeURIComponent(letter), url);
  return json({ error: 'Not found' }, 404);
}
