// The one place pages get data from. Today it reads hand-written fixtures; later the body of `getData`
// becomes calls through the API service binding to ti-api that forward the visitor's session, and no
// route changes. The `.server` suffix keeps this file and the fixtures out of the browser bundle.

import { normaliseId } from '@ti/core/ids';
import { NVD_NOTICE } from '@ti/core/licence';
import { SOURCES } from '@ti/sources/registry';
import { FIXTURE_CHANGES, FIXTURE_ENTRIES, type FixtureEntry } from './fixtures.server';
import type {
  EntryPreview,
  EntryResponse,
  EntryType,
  HomeData,
  IndexBucket,
  IndexResult,
  LicenceFilter,
  SearchParams,
  SearchResult,
  SiteData,
  SourceRow,
  SourcesResult,
} from './types';

/** True while pages show fixtures instead of live records. Drives the banner and `noindex`. */
export const SAMPLE_DATA = true;

export const MAX_RESULTS = 20;
export const MAX_QUERY = 200;
const KNOWN_SIGNALS = ['kev'];
const KNOWN_TYPES: EntryType[] = ['vuln', 'breach', 'ai', 'mal', 'tech', 'term'];
const LICENCE_STATUSES: LicenceFilter[] = ['on', 'ask', 'wait', 'link'];

const WAY_IN: Record<string, string> = {
  git: 'Git repository',
  changelist: 'Change list',
  since: 'API, changes since last run',
  fingerprint: 'Data file, checked for changes',
  feed: 'RSS or Atom feed',
  page: 'Web page',
  heavy: 'Large file, handled off-Worker',
};

function preview(e: FixtureEntry): EntryPreview {
  return {
    key: e.key,
    type: e.type,
    title: e.title,
    subtitle: e.subtitle,
    summary: e.summary,
    aliases: [...e.aliases],
    published: e.published,
    cvss: e.cvss,
    kev_added: e.kev_added,
  };
}

function byNewest(a: EntryPreview, b: EntryPreview): number {
  return (b.published ?? '').localeCompare(a.published ?? '') || a.key.localeCompare(b.key);
}

function credits(e: FixtureEntry): string[] {
  const lines: string[] = [];
  for (const id of e.sources) {
    const source = SOURCES.find((s) => s.id === id);
    if (source) lines.push(source.credit);
  }
  // The API's rule: the NVD notice appears once whenever NVD is cited.
  if (e.sources.includes('nvd') && !lines.includes(NVD_NOTICE)) lines.push(NVD_NOTICE);
  return [...new Set(lines)];
}

export function lookupEntry(id: string): EntryResponse | null {
  if (id.length > 100) return null;
  const wanted = normaliseId(id);
  const found = FIXTURE_ENTRIES.find(
    (e) => e.key === wanted || e.aliases.some((alias) => normaliseId(alias) === wanted),
  );
  if (!found) return null;
  return { access: 'preview', entry: preview(found), credits: credits(found) };
}

export function searchEntries(input: Partial<SearchParams>): SearchResult {
  const q = (input.q ?? '').slice(0, MAX_QUERY).trim();
  const type = (input.type ?? []).filter((t): t is EntryType => (KNOWN_TYPES as string[]).includes(t));
  const sig = (input.sig ?? []).filter((s) => KNOWN_SIGNALS.includes(s));
  const sort = input.sort ?? (q ? 'rel' : 'new');
  const params: SearchParams = { q, type, sig, sort: sort === 'new' ? 'new' : 'rel' };

  const needle = q.toLowerCase();
  const normalised = normaliseId(q).toLowerCase();
  let rows = FIXTURE_ENTRIES.filter((e) => {
    if (type.length > 0 && !type.includes(e.type)) return false;
    if (sig.includes('kev') && !e.kev_added) return false;
    if (!needle) return true;
    return [e.key, ...e.aliases, e.title, e.subtitle, e.summary].some((f) =>
      f.toLowerCase().includes(needle),
    );
  });

  const exact = (e: FixtureEntry) =>
    needle !== '' && [e.key, ...e.aliases].some((k) => normaliseId(k).toLowerCase() === normalised);
  rows = [...rows].sort((a, b) => {
    if (params.sort === 'new') return byNewest(a, b);
    return Number(exact(b)) - Number(exact(a)) || byNewest(a, b);
  });
  return { params, total: rows.length, results: rows.slice(0, MAX_RESULTS).map(preview) };
}

export function indexBucket(key: string): string {
  const first = key.charAt(0).toLowerCase();
  return first >= 'a' && first <= 'z' ? first : '0';
}

export function indexEntries(letter?: string | null): IndexResult {
  const all = FIXTURE_ENTRIES.map(preview).sort((a, b) => a.key.localeCompare(b.key));
  const buckets = new Map<string, IndexBucket>();
  for (const l of [...'abcdefghijklmnopqrstuvwxyz', '0'])
    buckets.set(l, { letter: l, count: 0, entries: [] });
  for (const e of all) {
    const b = buckets.get(indexBucket(e.key));
    if (b) {
      b.count += 1;
      b.entries.push(e);
    }
  }
  const list = [...buckets.values()];
  return { letter: letter ?? null, buckets: letter ? list.filter((b) => b.letter === letter) : list };
}

function sampleLastSuccess(index: number, cadence: string): string {
  const base = Date.UTC(2026, 10, 23, 9, 0, 0);
  const back = { '3h': 0, daily: 18, weekly: 24 * 4, monthly: 24 * 20, quarterly: 24 * 60 } as Record<
    string,
    number
  >;
  const hours = (back[cadence] ?? 12) + (index % 3);
  return new Date(base - hours * 3_600_000).toISOString();
}

export function listSources(status?: string | null): SourcesResult {
  const rows: SourceRow[] = SOURCES.map((s, i) => ({
    id: s.id,
    name: s.name,
    gives: s.gives,
    wayIn: WAY_IN[s.pattern] ?? s.pattern,
    cadence: s.cadence,
    licence: s.licence,
    lastSuccess: s.licence === 'wait' ? null : sampleLastSuccess(i, s.cadence),
  }));
  const counts = { all: rows.length, on: 0, ask: 0, wait: 0, link: 0 };
  for (const r of rows) counts[r.licence] += 1;
  const filter = LICENCE_STATUSES.find((s) => s === status) ?? null;
  return { status: filter, counts, rows: filter ? rows.filter((r) => r.licence === filter) : rows };
}

export function homeData(): HomeData {
  const count = (type: EntryType) => FIXTURE_ENTRIES.filter((e) => e.type === type).length;
  const previews = FIXTURE_ENTRIES.map(preview);
  return {
    tiles: [
      { type: 'vuln', label: 'Vulnerabilities', count: count('vuln') },
      { type: 'kev', label: 'Exploited in the wild', count: previews.filter((e) => e.kev_added).length },
      { type: 'breach', label: 'Breaches', count: count('breach') },
      { type: 'ai', label: 'AI incidents', count: count('ai') },
      { type: 'mal', label: 'Malicious packages', count: count('mal') },
    ],
    kev: previews
      .filter((e) => e.kev_added)
      .sort((a, b) => (b.kev_added ?? '').localeCompare(a.kev_added ?? ''))
      .slice(0, 5),
    breaches: previews
      .filter((e) => e.type === 'breach')
      .sort(byNewest)
      .slice(0, 5),
    changes: FIXTURE_CHANGES,
  };
}

/** What every loader calls. `request` is unused today; later it carries the session to forward to ti-api. */
export function getData(_request: Request): SiteData {
  return {
    home: homeData,
    search: searchEntries,
    entry: lookupEntry,
    index: indexEntries,
    sources: listSources,
  };
}
