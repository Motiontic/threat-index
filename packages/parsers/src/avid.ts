import type { IncidentRecord, ParseResult } from '@ti/core/types';
import { z } from 'zod';

/**
 * AVID (AI Vulnerability Database, github.com/avidml/avid-db, MIT). One report or vulnerability JSON file per
 * item: a `GitFile` from the git pattern, the document object, or its JSON text. Metadata only: titles, dates,
 * names and CWE ids, never the long description. Worker-safe: no Node-only imports.
 */
const Doc = z.looseObject({
  data_type: z.unknown().optional(),
  data_version: z.unknown().optional(),
  metadata: z.unknown().optional(),
  affects: z.unknown().optional(),
  problemtype: z.unknown().optional(),
  metrics: z.unknown().optional(),
  references: z.unknown().optional(),
  description: z.unknown().optional(),
  reports: z.unknown().optional(),
  impact: z.unknown().optional(),
  credit: z.unknown().optional(),
  published_date: z.unknown().optional(),
  last_modified_date: z.unknown().optional(),
  reported_date: z.unknown().optional(),
});

const KNOWN = new Set([
  'data_type',
  'data_version',
  'metadata',
  'affects',
  'problemtype',
  'metrics',
  'references',
  'description',
  'reports',
  'impact',
  'credit',
  'published_date',
  'last_modified_date',
  'reported_date',
]);

const AVID_ID = /^AVID-(\d{4})-([RV])\d{3,5}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const CWE = /^CWE-\d+$/;
const NOISE = new Set(['unknown', 'n/a', 'none']);

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** A `YYYY-MM-DD` cell that is a real date, else null. */
function day(cell: unknown): string | null {
  if (typeof cell !== 'string') return null;
  const s = cell.trim();
  if (!DAY.test(s)) return null;
  const d = new Date(`${s}T00:00:00.000Z`);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10) === s ? s : null;
}

/** Trimmed, whitespace collapsed, cut to 200 characters at a word boundary. */
function cleanTitle(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.replace(/\s+/g, ' ').trim();
  if (s.length <= 200) return s;
  const cut = s.slice(0, 200);
  if (s[200] === ' ') return cut.trimEnd();
  const i = cut.lastIndexOf(' ');
  return (i > 0 ? cut.slice(0, i) : cut).trimEnd();
}

function addEntities(out: string[], seen: Set<string>, list: unknown): void {
  if (!Array.isArray(list)) return;
  for (const item of list) {
    if (typeof item !== 'string') continue;
    const e = item.replace(/\s+/g, ' ').trim();
    if (!e || e.length > 100 || NOISE.has(e.toLowerCase()) || seen.has(e) || out.length >= 20) continue;
    seen.add(e);
    out.push(e);
  }
}

/** Reads a GitFile, a document object, or JSON text of either, down to the document object. */
function unwrap(input: unknown): Record<string, unknown> | null {
  let value = input;
  for (let depth = 0; depth < 3; depth++) {
    if (typeof value === 'string') {
      try {
        value = JSON.parse(value);
      } catch {
        throw new Error('avid: input is not valid JSON');
      }
    }
    if (!isObject(value)) throw new Error('avid: expected a report object, a GitFile or JSON text');
    if ('path' in value && 'status' in value && 'text' in value && !('data_type' in value)) {
      if (value.status === 'removed' || value.text === null || value.text === undefined) return null;
      value = value.text;
      continue;
    }
    return value;
  }
  throw new Error('avid: input is nested too deeply');
}

export function parseAvid(input: unknown): ParseResult<IncidentRecord> {
  const raw = unwrap(input);
  if (raw === null) return { records: [], unknownFields: [] };
  const doc = Doc.parse(raw);
  const unknown = new Set<string>();
  for (const key of Object.keys(doc)) if (!KNOWN.has(key)) unknown.add(key);
  const unknownFields = [...unknown];

  const meta = isObject(doc.metadata) ? doc.metadata : {};
  const id = [meta.report_id, meta.vuln_id].find((v) => v !== undefined && v !== null);
  const m = typeof id === 'string' ? AVID_ID.exec(id.trim()) : null;
  if (!m || typeof id !== 'string') return { records: [], unknownFields };
  const incidentId = id.trim();
  if (!SAFE_ID.test(incidentId)) return { records: [], unknownFields };

  const pt = isObject(doc.problemtype) ? doc.problemtype : {};
  const desc = isObject(pt.description) ? pt.description : {};
  const title = cleanTitle(desc.value) || incidentId;

  const date = day(doc.published_date) ?? day(doc.reported_date);

  const affects = isObject(doc.affects) ? doc.affects : {};
  const entities: string[] = [];
  const seen = new Set<string>();
  addEntities(entities, seen, affects.developer);
  addEntities(entities, seen, affects.deployer);
  if (Array.isArray(affects.artifacts)) {
    addEntities(
      entities,
      seen,
      affects.artifacts.map((a) => (isObject(a) ? a.name : undefined)),
    );
  }

  const techniques: string[] = [];
  const impact = isObject(doc.impact) ? doc.impact : {};
  if (Array.isArray(impact.cwe)) {
    for (const c of impact.cwe) {
      const cweId = isObject(c) && typeof c.cweId === 'string' ? c.cweId.trim() : '';
      if (CWE.test(cweId) && !techniques.includes(cweId)) techniques.push(cweId);
    }
  }

  const url =
    m[2] === 'R'
      ? `https://avidml.org/database/${incidentId.toLowerCase()}/`
      : `https://github.com/avidml/avid-db/blob/main/vulnerabilities/${m[1]}/${incidentId}.json`;

  const record: IncidentRecord = {
    source: 'avid',
    incidentId,
    kind: 'ai',
    title,
    ...(date ? { date } : {}),
    entities,
    techniques,
    url,
  };
  return { records: [record], unknownFields };
}

/** The parser-module contract: `@ti/parsers/<name>` exports `parse`. */
export const parse = parseAvid;
