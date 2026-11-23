// Hand-written guards for the API's JSON. Each checks the required fields and COPIES only the fields the
// pages use into a new object, so nothing else the API sends (an `access: 'full'` body, say) reaches a page.
// A guard throws `GuardError` on a missing or wrongly typed required field.
import type {
  Credit,
  EntryPreview,
  IndexLetterResponse,
  SearchHit,
  SearchResponse,
  SourceStatus,
  SourcesResponse,
} from '@ti/core/api';

export class GuardError extends Error {}

type Obj = Record<string, unknown>;

function obj(value: unknown, what: string): Obj {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new GuardError(`${what}: not an object`);
  return value as Obj;
}
function str(o: Obj, key: string, what: string): string {
  const v = o[key];
  if (typeof v !== 'string') throw new GuardError(`${what}.${key}: not a string`);
  return v;
}
function bool(o: Obj, key: string, what: string): boolean {
  const v = o[key];
  if (typeof v !== 'boolean') throw new GuardError(`${what}.${key}: not a boolean`);
  return v;
}
function num(o: Obj, key: string, what: string): number {
  const v = o[key];
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new GuardError(`${what}.${key}: not a number`);
  return v;
}
function optStr(o: Obj, key: string, what: string): string | undefined {
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
function arr(o: Obj, key: string, what: string): unknown[] {
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
