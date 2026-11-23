// An in-process stand-in for ti-api's public routes, over the hand-written fixtures. It answers in exactly the
// `@ti/core/api` shapes, so the pages and the client run the same code against fixtures and the real API.

import type {
  Credit,
  EntryFull,
  EntryPreview,
  IndexLetterResponse,
  SearchHit,
  SearchResponse,
  SourcesResponse,
} from '@ti/core/api';
import { normaliseId } from '@ti/core/ids';
import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCE_BY_ID, SOURCES } from '@ti/sources/registry';
import { fakeUserOf, fixtureAccountApi, fixtureFullEntry } from './fixture-account.server';
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

export async function fixtureApi(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === '/v1/me' || path.startsWith('/v1/me/')) return fixtureAccountApi(request, path);
  if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
  if (path === '/v1/search') return search(url);
  if (path === '/v1/sources') return sources();
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
