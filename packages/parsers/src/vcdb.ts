import type { IncidentRecord, ParseResult } from '@ti/core/types';

/**
 * VERIS Community Database incident, one JSON file each (the git pattern's `GitFile`, a JSON string,
 * or the parsed object). Only the victim name, the first action and variety, a date and a link are
 * kept, never `summary`, notes or other free text. CC BY-SA 4.0.
 */
export const MAX_TITLE = 200;

type Node = Record<string, unknown>;

const KNOWN = new Set([
  'schema_version',
  'schema_name',
  'incident_id',
  'source_id',
  'reference',
  'security_incident',
  'confidence',
  'summary',
  'related_incidents',
  'notes',
  'victim',
  'actor',
  'action',
  'asset',
  'attribute',
  'timeline',
  'discovery_method',
  'discovery_notes',
  'targeted',
  'impact',
  'plus',
  'cost_corrective_action',
  'control_failure',
  'corrective_action',
  'value_chain',
  'campaign_id',
]);
const ID_RE = /^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/;
const ACTIONS = ['hacking', 'malware', 'social', 'misuse', 'physical', 'error', 'environmental'] as const;

const obj = (v: unknown): Node | null =>
  typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Node) : null;

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

function isGitFile(v: Node): boolean {
  return typeof v.path === 'string' && 'text' in v && typeof v.status === 'string';
}

function dateOf(timeline: unknown): string | undefined {
  const t = obj(obj(timeline)?.incident);
  if (!t) return undefined;
  const { year, month, day } = t;
  if (![year, month, day].every((n) => typeof n === 'number' && Number.isInteger(n))) return undefined;
  const [y, m, d] = [year, month, day] as number[];
  if ((y as number) < 1000 || (y as number) > 9999) return undefined;
  const dt = new Date(Date.UTC(y as number, (m as number) - 1, d as number));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== (m as number) - 1 || dt.getUTCDate() !== d) {
    return undefined;
  }
  return dt.toISOString().slice(0, 10);
}

function urlOf(reference: unknown, plus: unknown): string | undefined {
  for (const part of str(reference).split(/[\s;,]+/)) {
    try {
      const u = new URL(part);
      if (u.protocol === 'http:' || u.protocol === 'https:') return part;
    } catch {
      // not a URL
    }
  }
  const gh = obj(plus)?.github;
  const n = typeof gh === 'number' ? String(gh) : str(gh);
  return /^\d+$/.test(n) ? `https://github.com/vz-risk/VCDB/issues/${n}` : undefined;
}

export function parseVcdb(input: unknown): ParseResult<IncidentRecord> {
  let value = input;
  if (obj(value) && isGitFile(value as Node)) {
    const f = value as Node;
    if (f.status === 'removed' || f.text === null) return { records: [], unknownFields: [] };
    value = f.text;
  }
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('vcdb: input is not valid JSON');
    }
  }
  const inc = obj(value);
  if (!inc) throw new Error('vcdb: expected an incident object');
  const rawId = str(inc.incident_id);
  if (!ID_RE.test(rawId)) throw new Error('vcdb: missing or invalid incident_id');
  const unknownFields = Object.keys(inc).filter((k) => !KNOWN.has(k));
  if (inc.security_incident !== 'Confirmed') return { records: [], unknownFields };

  const victimId = str(obj(inc.victim)?.victim_id);
  const named = victimId !== '' && victimId.toLowerCase() !== 'unknown';
  const victim = named ? victimId : 'Unnamed organisation';

  const action = obj(inc.action);
  const key = ACTIONS.find((a) => action && a in action);
  let title: string;
  if (key) {
    const varieties = obj(action?.[key])?.variety;
    const first = Array.isArray(varieties) ? str(varieties[0]) : '';
    const label = key.charAt(0).toUpperCase() + key.slice(1);
    title = `${victim}: ${label}${first !== '' && first.toLowerCase() !== 'unknown' ? ` (${first})` : ''}`;
  } else {
    title = `${victim}: incident`;
  }

  const date = dateOf(inc.timeline);
  const url = urlOf(inc.reference, inc.plus);
  const record: IncidentRecord = {
    source: 'vcdb',
    incidentId: rawId.toUpperCase(),
    kind: 'cyber_event',
    title: title.slice(0, MAX_TITLE),
    ...(date ? { date } : {}),
    ...(named ? { entities: [victimId] } : {}),
    ...(url ? { url } : {}),
  };
  return { records: [record], unknownFields };
}

export const parse = parseVcdb;
