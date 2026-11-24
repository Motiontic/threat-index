// Hand-written guards for the API's JSON. Each checks the required fields and COPIES only the fields the
// pages use into a new object, so nothing else the API sends (an `access: 'full'` body, say) reaches a page.
// A guard throws `GuardError` on a missing or wrongly typed required field.
import type {
  AlertSettings,
  DigestCadence,
  Me,
  SavedSearch,
  SavedSearchListResponse,
  SavedSearchParams,
  WatchItem,
  WatchListResponse,
} from '@ti/core/account';
import type {
  Credit,
  EntryPreview,
  HomeChange,
  HomeCounts,
  HomeItem,
  HomeLists,
  HomeResponse,
  IndexLetterResponse,
  SearchHit,
  SearchResponse,
  SourceStatus,
  SourcesResponse,
} from '@ti/core/api';
import type { EntryFullView } from './types';

export class GuardError extends Error {}

export type Obj = Record<string, unknown>;

export function obj(value: unknown, what: string): Obj {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new GuardError(`${what}: not an object`);
  return value as Obj;
}
export function str(o: Obj, key: string, what: string): string {
  const v = o[key];
  if (typeof v !== 'string') throw new GuardError(`${what}.${key}: not a string`);
  return v;
}
export function bool(o: Obj, key: string, what: string): boolean {
  const v = o[key];
  if (typeof v !== 'boolean') throw new GuardError(`${what}.${key}: not a boolean`);
  return v;
}
export function num(o: Obj, key: string, what: string): number {
  const v = o[key];
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new GuardError(`${what}.${key}: not a number`);
  return v;
}
export function optStr(o: Obj, key: string, what: string): string | undefined {
  const v = o[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string') throw new GuardError(`${what}.${key}: not a string`);
  return v;
}
function optNum(o: Obj, key: string, what: string): number | undefined {
  const v = o[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new GuardError(`${what}.${key}: not a number`);
  return v;
}
export function arr(o: Obj, key: string, what: string): unknown[] {
  const v = o[key];
  if (!Array.isArray(v)) throw new GuardError(`${what}.${key}: not an array`);
  return v;
}
/** Sets `key` only when the value is defined, so objects carry no `undefined` fields. */
function put<T extends object, K extends string, V>(target: T, key: K, value: V | undefined): void {
  if (value !== undefined) (target as Record<string, unknown>)[key] = value;
}

export function guardCredit(value: unknown): Credit {
  const o = obj(value, 'credit');
  const out: Credit = {
    sourceId: str(o, 'sourceId', 'credit'),
    name: str(o, 'name', 'credit'),
    text: str(o, 'text', 'credit'),
  };
  put(out, 'url', optStr(o, 'url', 'credit'));
  return out;
}

export function guardEntryPreview(value: unknown): EntryPreview {
  const o = obj(value, 'entry');
  const out: EntryPreview = {
    key: str(o, 'key', 'entry'),
    kind: str(o, 'kind', 'entry'),
    title: str(o, 'title', 'entry'),
    summary: str(o, 'summary', 'entry'),
    aliases: arr(o, 'aliases', 'entry').map((a) => {
      if (typeof a !== 'string') throw new GuardError('entry.aliases: not strings');
      return a;
    }),
    exploited: bool(o, 'exploited', 'entry'),
    credits: [],
  };
  put(out, 'published', optStr(o, 'published', 'entry'));
  put(out, 'modified', optStr(o, 'modified', 'entry'));
  put(out, 'cvss', optNum(o, 'cvss', 'entry'));
  put(out, 'cvssVersion', optStr(o, 'cvssVersion', 'entry'));
  put(out, 'kevAdded', optStr(o, 'kevAdded', 'entry'));
  put(out, 'epss', optNum(o, 'epss', 'entry'));
  return out;
}

/** `{ access, entry, credits }`. The API sends credits beside the entry; a `full` entry is cut to preview fields. */
export function guardEntryResponse(value: unknown): EntryPreview {
  const o = obj(value, 'response');
  const access = str(o, 'access', 'response');
  if (access !== 'preview' && access !== 'full') throw new GuardError('response.access: unknown');
  const entry = guardEntryPreview(o.entry);
  // Credits live on the entry in the shared type; accept them on either object.
  const raw = Array.isArray(obj(o.entry, 'entry').credits) ? obj(o.entry, 'entry').credits : o.credits;
  if (!Array.isArray(raw)) throw new GuardError('response: no credits');
  entry.credits = raw.map(guardCredit);
  return entry;
}

export function guardSearchHit(value: unknown): SearchHit & { kind?: string } {
  const o = obj(value, 'hit');
  const out: SearchHit & { kind?: string } = {
    key: str(o, 'key', 'hit'),
    title: str(o, 'title', 'hit'),
    summary: str(o, 'summary', 'hit'),
    exploited: bool(o, 'exploited', 'hit'),
  };
  put(out, 'cvss', optNum(o, 'cvss', 'hit'));
  put(out, 'published', optStr(o, 'published', 'hit'));
  put(out, 'kind', optStr(o, 'kind', 'hit'));
  return out;
}

export function guardSearchResponse(value: unknown): SearchResponse {
  const o = obj(value, 'search');
  const out: SearchResponse = {
    query: str(o, 'query', 'search'),
    hits: arr(o, 'hits', 'search').map(guardSearchHit),
    total: num(o, 'total', 'search'),
    credits: arr(o, 'credits', 'search').map(guardCredit),
  };
  put(out, 'cursor', optStr(o, 'cursor', 'search'));
  return out;
}

export function guardIndexLetter(value: unknown): IndexLetterResponse {
  const o = obj(value, 'index');
  const out: IndexLetterResponse = {
    letter: str(o, 'letter', 'index'),
    items: arr(o, 'items', 'index').map((i) => {
      const item = obj(i, 'index item');
      return { key: str(item, 'key', 'index item'), title: str(item, 'title', 'index item') };
    }),
  };
  put(out, 'cursor', optStr(o, 'cursor', 'index'));
  return out;
}

const LICENCES = ['on', 'ask', 'wait', 'link'] as const;
const DISPLAYS = ['full', 'link', 'hidden'] as const;

export function guardSourceStatus(value: unknown): SourceStatus {
  const o = obj(value, 'source');
  const licence = str(o, 'licence', 'source');
  const display = str(o, 'display', 'source');
  if (!(LICENCES as readonly string[]).includes(licence)) throw new GuardError('source.licence: unknown');
  if (!(DISPLAYS as readonly string[]).includes(display)) throw new GuardError('source.display: unknown');
  const out: SourceStatus = {
    id: str(o, 'id', 'source'),
    name: str(o, 'name', 'source'),
    gives: str(o, 'gives', 'source'),
    pattern: str(o, 'pattern', 'source'),
    cadence: str(o, 'cadence', 'source'),
    licence: licence as SourceStatus['licence'],
    display: display as SourceStatus['display'],
    credit: str(o, 'credit', 'source'),
  };
  put(out, 'lastSuccess', optStr(o, 'lastSuccess', 'source'));
  put(out, 'lastRunStatus', optStr(o, 'lastRunStatus', 'source'));
  return out;
}

export function guardSources(value: unknown): SourcesResponse {
  const o = obj(value, 'sources');
  return { sources: arr(o, 'sources', 'sources').map(guardSourceStatus) };
}

export function guardApiError(value: unknown): string {
  const o = obj(value, 'error');
  return str(o, 'error', 'error');
}

// ---- Signed-in responses ----

/** Only http(s) links reach a page; `javascript:`, `data:` and the rest are dropped. */
export function safeUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

function strList(o: Obj, key: string, what: string): string[] {
  return arr(o, key, what).map((v) => {
    if (typeof v !== 'string') throw new GuardError(`${what}.${key}: not strings`);
    return v;
  });
}

const CADENCES: readonly string[] = ['daily', 'weekly', 'off'];

function guardAlerts(value: unknown): AlertSettings {
  const o = obj(value, 'alerts');
  const digest = str(o, 'digest', 'alerts');
  if (!CADENCES.includes(digest)) throw new GuardError('alerts.digest: unknown');
  const weekday = num(o, 'digestWeekday', 'alerts');
  if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6)
    throw new GuardError('alerts.digestWeekday: out of range');
  return { instant: bool(o, 'instant', 'alerts'), digest: digest as DigestCadence, digestWeekday: weekday };
}

export function guardMe(value: unknown): Me {
  const o = obj(value, 'me');
  const name = o.displayName;
  if (name !== null && name !== undefined && typeof name !== 'string')
    throw new GuardError('me.displayName: not a string');
  return {
    userId: str(o, 'userId', 'me'),
    email: str(o, 'email', 'me'),
    displayName: typeof name === 'string' ? name : null,
    alerts: guardAlerts(o.alerts),
  };
}

export function guardWatchItem(value: unknown): WatchItem {
  const o = obj(value, 'watch item');
  return {
    entryKey: str(o, 'entryKey', 'watch item'),
    title: str(o, 'title', 'watch item'),
    alertsOn: bool(o, 'alertsOn', 'watch item'),
    createdAt: str(o, 'createdAt', 'watch item'),
  };
}

export function guardWatchList(value: unknown): WatchListResponse {
  const o = obj(value, 'watch list');
  return { items: arr(o, 'items', 'watch list').map(guardWatchItem), limit: num(o, 'limit', 'watch list') };
}

function guardSavedParams(value: unknown): SavedSearchParams {
  if (value === undefined || value === null) return {};
  const o = obj(value, 'params');
  const out: SavedSearchParams = {};
  for (const k of ['type', 'sig', 'sev', 'year'] as const) {
    if (o[k] !== undefined) out[k] = strList(o, k, 'params');
  }
  if (o.sort === 'rel' || o.sort === 'new') out.sort = o.sort;
  return out;
}

export function guardSavedSearch(value: unknown): SavedSearch {
  const o = obj(value, 'saved search');
  return {
    id: str(o, 'id', 'saved search'),
    name: str(o, 'name', 'saved search'),
    query: str(o, 'query', 'saved search'),
    params: guardSavedParams(o.params),
    alertsOn: bool(o, 'alertsOn', 'saved search'),
    createdAt: str(o, 'createdAt', 'saved search'),
  };
}

export function guardSavedList(value: unknown): SavedSearchListResponse {
  const o = obj(value, 'saved list');
  return {
    items: arr(o, 'items', 'saved list').map(guardSavedSearch),
    limit: num(o, 'limit', 'saved list'),
  };
}

/**
 * The full entry: `access: 'full'` only (a `preview` answer is null: the page keeps the preview). Fields are
 * copied; advisories with `display: 'hidden'` are dropped and `link` ones keep only source, id and URL.
 */
export function guardEntryFull(value: unknown): EntryFullView | null {
  const o = obj(value, 'response');
  if (str(o, 'access', 'response') !== 'full') return null;
  const base = guardEntryResponse(value);
  const e = obj(o.entry, 'entry');
  const advisories: EntryFullView['advisories'] = [];
  for (const raw of arr(e, 'advisories', 'entry')) {
    const a = obj(raw, 'advisory');
    const display = str(a, 'display', 'advisory');
    if (display === 'hidden') continue;
    if (display !== 'full' && display !== 'link') throw new GuardError('advisory.display: unknown');
    const out: EntryFullView['advisories'][number] = {
      source: str(a, 'source', 'advisory'),
      sourceId: str(a, 'sourceId', 'advisory'),
      status: display === 'link' ? '' : str(a, 'status', 'advisory'),
      display,
    };
    put(out, 'url', safeUrl(optStr(a, 'url', 'advisory')));
    if (display === 'full') {
      put(out, 'published', optStr(a, 'published', 'advisory'));
      put(out, 'modified', optStr(a, 'modified', 'advisory'));
      if (Array.isArray(a.affected)) {
        out.affected = a.affected.slice(0, 200).map((x) => {
          const r = obj(x, 'affected');
          const item: NonNullable<typeof out.affected>[number] = {
            ecosystem: str(r, 'ecosystem', 'affected'),
            name: str(r, 'name', 'affected'),
          };
          put(item, 'introduced', optStr(r, 'introduced', 'affected'));
          put(item, 'fixed', optStr(r, 'fixed', 'affected'));
          put(item, 'range', optStr(r, 'range', 'affected'));
          return item;
        });
      }
    }
    advisories.push(out);
  }
  const signals = arr(e, 'signals', 'entry').map((raw) => {
    const s = obj(raw, 'signal');
    const out: EntryFullView['signals'][number] = {
      kind: str(s, 'kind', 'signal'),
      source: str(s, 'source', 'signal'),
      ref: str(s, 'ref', 'signal'),
      firstSeen: str(s, 'firstSeen', 'signal'),
    };
    put(out, 'url', safeUrl(optStr(s, 'url', 'signal')));
    return out;
  });
  const changes = arr(e, 'changes', 'entry').map((raw) => {
    const c = obj(raw, 'change');
    const out: EntryFullView['changes'][number] = {
      kind: str(c, 'kind', 'change'),
      at: str(c, 'at', 'change'),
    };
    put(out, 'old', optStr(c, 'old', 'change'));
    put(out, 'new', optStr(c, 'new', 'change'));
    put(out, 'source', optStr(c, 'source', 'change'));
    return out;
  });
  return { ...base, cwe: strList(e, 'cwe', 'entry'), advisories, signals, changes };
}

const HOME_MAX = 10;
const HOME_TYPES: HomeItem['type'][] = ['vuln', 'breach', 'ai', 'mal'];

function guardHomeItem(value: unknown): HomeItem {
  const o = obj(value, 'home item');
  const type = str(o, 'type', 'home item') as HomeItem['type'];
  if (!HOME_TYPES.includes(type)) throw new GuardError('home item.type: unknown');
  const out: HomeItem = { key: str(o, 'key', 'home item'), title: str(o, 'title', 'home item'), type };
  put(out, 'source', optStr(o, 'source', 'home item'));
  put(out, 'date', optStr(o, 'date', 'home item'));
  put(out, 'signal', optStr(o, 'signal', 'home item'));
  return out;
}

function guardHomeChange(value: unknown): HomeChange {
  const o = obj(value, 'home change');
  const type = str(o, 'type', 'home change');
  if (type !== 'vuln' && type !== 'breach') throw new GuardError('home change.type: unknown');
  const out: HomeChange = {
    key: str(o, 'key', 'home change'),
    kind: str(o, 'kind', 'home change'),
    at: str(o, 'at', 'home change'),
    type,
  };
  put(out, 'title', optStr(o, 'title', 'home change'));
  put(out, 'source', optStr(o, 'source', 'home change'));
  return out;
}

const COUNT_KEYS: (keyof HomeCounts)[] = [
  'vulnerabilities',
  'exploited',
  'exploits',
  'breaches',
  'aiIncidents',
  'cyberOperations',
  'maliciousPackages',
  'techniques',
];
const LIST_KEYS: (keyof HomeLists)[] = [
  'exploited',
  'vulnerabilities',
  'exploits',
  'breaches',
  'aiIncidents',
  'maliciousPackages',
];

export function guardHome(value: unknown): HomeResponse {
  const o = obj(value, 'home');
  const c = obj(o.counts, 'home.counts');
  const l = obj(o.lists, 'home.lists');
  const counts = {} as HomeCounts;
  for (const k of COUNT_KEYS) counts[k] = Math.max(0, Math.trunc(num(c, k, 'home.counts')));
  const lists = {} as HomeLists;
  for (const k of LIST_KEYS) lists[k] = arr(l, k, 'home.lists').slice(0, HOME_MAX).map(guardHomeItem);
  return { counts, lists, changes: arr(o, 'changes', 'home').slice(0, HOME_MAX).map(guardHomeChange) };
}
