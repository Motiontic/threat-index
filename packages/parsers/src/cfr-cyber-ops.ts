import type { IncidentRecord, ParseResult } from '@ti/core/types';
import { z } from 'zod';

/**
 * Council on Foreign Relations Cyber Operations Tracker, one CSV row per operation (the fingerprint pattern's
 * item body). No licence checked; source marked `ask`. Metadata only: title, date, sponsor, affiliations and a
 * source link; `Victims`, `Description` and `Response` are not stored.
 */
const Row = z.looseObject({
  Title: z.unknown(),
  Date: z.unknown().optional(),
  Affiliations: z.unknown().optional(),
  Description: z.unknown().optional(),
  Response: z.unknown().optional(),
  Victims: z.unknown().optional(),
  Sponsor: z.unknown().optional(),
  Type: z.unknown().optional(),
  Category: z.unknown().optional(),
  Sources_1: z.unknown().optional(),
  Sources_2: z.unknown().optional(),
  Sources_3: z.unknown().optional(),
});

const KNOWN = new Set([
  'Title',
  'Date',
  'Affiliations',
  'Description',
  'Response',
  'Victims',
  'Sponsor',
  'Type',
  'Category',
  'Sources_1',
  'Sources_2',
  'Sources_3',
]);

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const NOISE = new Set(['unknown', 'n/a', 'none']);

function day(cell: unknown): string | null {
  if (typeof cell !== 'string') return null;
  const s = cell.trim();
  if (!DAY.test(s)) return null;
  const d = new Date(`${s}T00:00:00.000Z`);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10) === s ? s : null;
}

function httpUrl(cell: unknown): string | null {
  if (typeof cell !== 'string') return null;
  const s = cell.trim();
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:' ? s : null;
  } catch {
    return null;
  }
}

/** The FNV-1a 32-bit hash of the string's UTF-16 code units, as 8 hex digits. */
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/**
 * `<date or 'undated'>:<slug>:<hash>`. The CSV has no ID of its own, so an edit to the title, the date or the
 * affiliations gives a new ID (and so a new incident row). The hash keeps apart rows that share a title and a
 * date, like the two "Roshan" rows. The arguments are the raw trimmed cells.
 */
export function cfrIncidentId(title: string, date: string | null, affiliations: string): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/g, '');
  const hash = fnv1a(`${title}\u001f${date ?? ''}\u001f${affiliations}`);
  return `${date ?? 'undated'}:${slug}:${hash}`;
}

function cleanTitle(s: string): string {
  const t = s.replace(/\s+/g, ' ').trim();
  if (t.length <= 200) return t;
  const cut = t.slice(0, 200);
  if (t[200] === ' ') return cut.trimEnd();
  const i = cut.lastIndexOf(' ');
  return (i > 0 ? cut.slice(0, i) : cut).trimEnd();
}

function names(affiliations: string): string[] {
  const s = affiliations.replace(/^\s*also known as\s+/i, '');
  return s
    .split(/\s*[,;]\s*(?:and\s+)?|\s+and\s+/i)
    .map((p) => p.replace(/\s+/g, ' ').trim().replace(/\.$/, '').trim());
}

export function parseCfrRow(input: unknown): ParseResult<IncidentRecord> {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('cfr-cyber-ops: input is not valid JSON');
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !('Title' in value)) {
    throw new Error('cfr-cyber-ops: expected a row object with a Title key');
  }
  const row = Row.parse(value);
  const unknown = new Set<string>();
  for (const key of Object.keys(row)) if (!KNOWN.has(key)) unknown.add(key);
  const unknownFields = [...unknown];

  const rawTitle = typeof row.Title === 'string' ? row.Title.trim() : '';
  const title = cleanTitle(rawTitle);
  if (!title) return { records: [], unknownFields };
  const date = day(row.Date);
  const affiliations = typeof row.Affiliations === 'string' ? row.Affiliations.trim() : '';
  const incidentId = cfrIncidentId(rawTitle, date, affiliations);
  if (!SAFE_ID.test(incidentId)) return { records: [], unknownFields };

  const entities: string[] = [];
  const seen = new Set<string>();
  // Sponsor is one name: commas belong to names like "Korea (Democratic People's Republic of)".
  const sponsor = typeof row.Sponsor === 'string' ? [row.Sponsor] : [];
  for (const raw of [...sponsor, ...names(affiliations)]) {
    const e = raw.replace(/\s+/g, ' ').trim();
    if (!e || e.length > 100 || NOISE.has(e.toLowerCase()) || seen.has(e) || entities.length >= 20) continue;
    seen.add(e);
    entities.push(e);
  }

  const url = httpUrl(row.Sources_1) ?? httpUrl(row.Sources_2) ?? httpUrl(row.Sources_3);
  const record: IncidentRecord = {
    source: 'cfr-tracker',
    incidentId,
    kind: 'cyber_op',
    title,
    ...(date ? { date } : {}),
    entities,
    ...(url ? { url } : {}),
  };
  return { records: [record], unknownFields };
}

/** The parser-module contract: `@ti/parsers/<name>` exports `parse`. */
export const parse = parseCfrRow;
