// Guards for the world routes (breaches, incidents, techniques). Same rules as guards.ts: required fields are
// checked, only known fields are copied, `http(s)` is the only URL scheme that survives, lists are capped, and a
// body that carries a `total` anywhere is refused, because a breach count is never summed.
import type {
  BreachCount,
  BreachDetail,
  BreachNotice,
  BreachSummary,
  CountUnit,
  Framework,
  IncidentDetail,
  IncidentKind,
  IncidentSummary,
  TechniqueDetail,
  TechniqueSummary,
  WorldList,
} from '@ti/core/world-api';
import { GuardError, guardCredit } from './guards';

type Obj = Record<string, unknown>;

export const MAX_ITEMS = 25;
export const MAX_NOTICES = 200;
export const MAX_CHILDREN = 200;
export const MAX_VULNS = 50;
const MAX_SMALL = 200;

const UNITS: CountUnit[] = ['state_residents', 'individuals', 'accounts', 'not_stated', 'claim'];
const KINDS: IncidentKind[] = ['ai', 'cyber_op', 'cyber_event'];
const FRAMEWORKS: Framework[] = ['attack', 'atlas', 'cwe', 'capec'];

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
function optStr(o: Obj, key: string, what: string): string | undefined {
  const v = o[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string') throw new GuardError(`${what}.${key}: not a string`);
  return v;
}
function num(o: Obj, key: string, what: string): number {
  const v = o[key];
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new GuardError(`${what}.${key}: not a number`);
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
function strings(o: Obj, key: string, what: string, max: number): string[] {
  return arr(o, key, what)
    .slice(0, max)
    .map((v, i) => {
      if (typeof v !== 'string') throw new GuardError(`${what}.${key}[${i}]: not a string`);
      return v;
    });
}
function put<T extends object>(target: T, key: string, value: unknown): void {
  if (value !== undefined) (target as Record<string, unknown>)[key] = value;
}
function oneOf<T extends string>(v: unknown, allowed: readonly T[], what: string): T {
  if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v))
    throw new GuardError(`${what}: unknown value`);
  return v as T;
}
/** Only `http:` and `https:` links survive. */
export function httpUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const p = new URL(url).protocol;
    return p === 'http:' || p === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

/** Throws when any object in the body has a `total` key. */
function noTotal(value: unknown, depth = 0): void {
  if (depth > 6 || typeof value !== 'object' || value === null) return;
  if (Array.isArray(value)) {
    for (const v of value) noTotal(v, depth + 1);
    return;
  }
  if ('total' in value) throw new GuardError('body carries a total');
  for (const v of Object.values(value)) noTotal(v, depth + 1);
}

function credits(o: Obj, what: string) {
  return arr(o, 'credits', what).slice(0, MAX_SMALL).map(guardCredit);
}

function list<T>(value: unknown, what: string, item: (v: unknown) => T): WorldList<T> {
  noTotal(value);
  const o = obj(value, what);
  const nextRaw = o.next;
  if (nextRaw !== null && nextRaw !== undefined && (typeof nextRaw !== 'number' || !Number.isFinite(nextRaw)))
    throw new GuardError(`${what}.next: not a number`);
  return {
    items: arr(o, 'items', what).slice(0, MAX_ITEMS).map(item),
    page: num(o, 'page', what),
    next: typeof nextRaw === 'number' ? nextRaw : null,
    credits: credits(o, what),
  };
}

function guardCount(value: unknown): BreachCount {
  const o = obj(value, 'count');
  return {
    unit: oneOf(o.unit, UNITS, 'count.unit'),
    jurisdiction: optStr(o, 'jurisdiction', 'count') ?? null,
    count: num(o, 'count', 'count'),
  };
}

function guardBreachSummary(value: unknown): BreachSummary {
  const o = obj(value, 'breach');
  const c = o.company === null || o.company === undefined ? null : obj(o.company, 'breach.company');
  const out: BreachSummary = {
    key: str(o, 'key', 'breach'),
    company: c ? { key: str(c, 'key', 'company'), name: str(c, 'name', 'company') } : null,
    firstSeen: str(o, 'firstSeen', 'breach'),
    noticeCount: num(o, 'noticeCount', 'breach'),
    counts: arr(o, 'counts', 'breach').slice(0, MAX_SMALL).map(guardCount),
    jurisdictions: strings(o, 'jurisdictions', 'breach', MAX_SMALL),
    sources: strings(o, 'sources', 'breach', MAX_SMALL),
  };
  if (o.dates !== undefined && o.dates !== null) {
    const d = obj(o.dates, 'breach.dates');
    out.dates = { from: str(d, 'from', 'dates'), to: str(d, 'to', 'dates') };
  }
  return out;
}

function guardNotice(value: unknown): BreachNotice {
  const o = obj(value, 'notice');
  const display = oneOf(o.display, ['full', 'link'] as const, 'notice.display');
  const out: BreachNotice = {
    source: str(o, 'source', 'notice'),
    noticeId: str(o, 'noticeId', 'notice'),
    name: str(o, 'name', 'notice'),
    display,
  };
  put(out, 'notified', optStr(o, 'notified', 'notice'));
  put(out, 'url', httpUrl(optStr(o, 'url', 'notice')));
  // A link notice shows id, name, date and link only, whatever else the body carries.
  if (display === 'full') {
    put(out, 'occurredFrom', optStr(o, 'occurredFrom', 'notice'));
    put(out, 'occurredTo', optStr(o, 'occurredTo', 'notice'));
    put(out, 'discovered', optStr(o, 'discovered', 'notice'));
    put(out, 'count', optNum(o, 'count', 'notice'));
    if (o.countUnit !== undefined && o.countUnit !== null)
      out.countUnit = oneOf(o.countUnit, UNITS, 'notice.countUnit');
    put(out, 'jurisdiction', optStr(o, 'jurisdiction', 'notice'));
    if (o.dataTypes !== undefined) out.dataTypes = strings(o, 'dataTypes', 'notice', MAX_SMALL);
  }
  return out;
}

export const guardBreachList = (v: unknown) => list(v, 'breaches', guardBreachSummary);

export function guardBreachDetail(value: unknown): BreachDetail {
  noTotal(value);
  const o = obj(value, 'breach');
  return {
    ...guardBreachSummary(o),
    notices: arr(o, 'notices', 'breach').slice(0, MAX_NOTICES).map(guardNotice),
    credits: credits(o, 'breach'),
  };
}

function guardIncidentSummary(value: unknown): IncidentSummary {
  const o = obj(value, 'incident');
  const out: IncidentSummary = {
    source: str(o, 'source', 'incident'),
    incidentId: str(o, 'incidentId', 'incident'),
    kind: oneOf(o.kind, KINDS, 'incident.kind'),
    title: str(o, 'title', 'incident'),
    display: oneOf(o.display, ['full', 'link'] as const, 'incident.display'),
  };
  put(out, 'date', optStr(o, 'date', 'incident'));
  put(out, 'url', httpUrl(optStr(o, 'url', 'incident')));
  return out;
}

export const guardIncidentList = (v: unknown) => list(v, 'incidents', guardIncidentSummary);

export function guardIncidentDetail(value: unknown): IncidentDetail {
  noTotal(value);
  const o = obj(value, 'incident');
  const base = guardIncidentSummary(o);
  const full = base.display === 'full';
  return {
    ...base,
    entities: full ? strings(o, 'entities', 'incident', MAX_SMALL) : [],
    techniques: full
      ? arr(o, 'techniques', 'incident')
          .slice(0, MAX_VULNS)
          .map((t) => {
            const to = obj(t, 'incident.technique');
            const out: { id: string; name?: string } = { id: str(to, 'id', 'technique') };
            put(out, 'name', optStr(to, 'name', 'technique'));
            return out;
          })
      : [],
    credits: credits(o, 'incident'),
  };
}

function guardTechniqueSummary(value: unknown): TechniqueSummary {
  const o = obj(value, 'technique');
  const out: TechniqueSummary = {
    id: str(o, 'id', 'technique'),
    framework: oneOf(o.framework, FRAMEWORKS, 'technique.framework'),
    name: str(o, 'name', 'technique'),
  };
  put(out, 'parent', optStr(o, 'parent', 'technique'));
  return out;
}

export const guardTechniqueList = (v: unknown) => list(v, 'techniques', guardTechniqueSummary);

export function guardTechniqueDetail(value: unknown): TechniqueDetail {
  noTotal(value);
  const o = obj(value, 'technique');
  const out: TechniqueDetail = {
    ...guardTechniqueSummary(o),
    children: arr(o, 'children', 'technique').slice(0, MAX_CHILDREN).map(guardTechniqueSummary),
    vulns: arr(o, 'vulns', 'technique')
      .slice(0, MAX_VULNS)
      .map((v) => {
        const vo = obj(v, 'technique.vuln');
        const item: TechniqueDetail['vulns'][number] = {
          key: str(vo, 'key', 'vuln'),
          title: str(vo, 'title', 'vuln'),
          exploited: vo.exploited === true,
        };
        put(item, 'cvss', optNum(vo, 'cvss', 'vuln'));
        return item;
      }),
    vulnsMore: o.vulnsMore === true,
    credits: credits(o, 'technique'),
  };
  put(out, 'summary', optStr(o, 'summary', 'technique'));
  if (o.parentRef !== undefined && o.parentRef !== null) {
    const p = obj(o.parentRef, 'technique.parentRef');
    out.parentRef = { id: str(p, 'id', 'parentRef'), name: str(p, 'name', 'parentRef') };
  }
  return out;
}
