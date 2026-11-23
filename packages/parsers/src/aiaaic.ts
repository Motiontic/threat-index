import type { IncidentRecord, ParseResult } from '@ti/core/types';
import { z } from 'zod';

/**
 * AIAAIC repository, tab "Incidents" (a Google Sheet's CSV export), one CSV row per incident (the fingerprint
 * pattern's item body). No licence checked; source marked `ask`. Metadata only: headline, deployer, developer,
 * system name and the incident's aiaaic.org page; no summary or taxonomy text.
 */
const Row = z.looseObject({
  'AIAAIC ID#': z.unknown(),
  'Incident headline': z.unknown().optional(),
  Occurred: z.unknown().optional(),
  Deployer: z.unknown().optional(),
  Developer: z.unknown().optional(),
  'System name': z.unknown().optional(),
  'Summary/links': z.unknown().optional(),
});

const KNOWN = new Set([
  'AIAAIC ID#',
  'Incident headline',
  'Occurred',
  'Deployer',
  'Developer',
  'System name',
  'Technology',
  'Purpose',
  'News trigger (taxonomy)',
  'Ethical issue (taxonomy)',
  'Impacted area',
  '',
  'External harm (taxonomy)',
  'Harm status',
  'Consequence (taxonomy)',
  'Response (taxonomy)',
  'Summary/links',
]);

const ID = /^AIAAIC\d+$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const NOISE = new Set(['unknown', 'n/a', 'none']);

/** A `YYYY-MM-DD` cell that is a real date, else null. A year or a range (`2023-2024`) is null. */
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

export function parseAiaaicRow(input: unknown): ParseResult<IncidentRecord> {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('aiaaic: input is not valid JSON');
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !('AIAAIC ID#' in value)) {
    throw new Error('aiaaic: expected a row object with an AIAAIC ID# key');
  }
  const row = Row.parse(value);
  const unknown = new Set<string>();
  for (const key of Object.keys(row)) if (!KNOWN.has(key)) unknown.add(key);
  const unknownFields = [...unknown];

  const idCell = row['AIAAIC ID#'];
  const incidentId = typeof idCell === 'string' ? idCell.trim() : '';
  if (!ID.test(incidentId) || !SAFE_ID.test(incidentId)) return { records: [], unknownFields };
  const title = cleanTitle(row['Incident headline']);
  if (!title) return { records: [], unknownFields };

  const entities: string[] = [];
  const seen = new Set<string>();
  for (const cell of [row.Deployer, row.Developer, row['System name']]) {
    if (typeof cell !== 'string') continue;
    for (const part of cell.split(';')) {
      const e = part.replace(/\s+/g, ' ').trim();
      if (!e || e.length > 100 || NOISE.has(e.toLowerCase()) || seen.has(e) || entities.length >= 20)
        continue;
      seen.add(e);
      entities.push(e);
    }
  }

  const date = day(row.Occurred);
  const url = httpUrl(row['Summary/links']);
  const record: IncidentRecord = {
    source: 'aiaaic',
    incidentId,
    kind: 'ai',
    title,
    ...(date ? { date } : {}),
    entities,
    ...(url ? { url } : {}),
  };
  return { records: [record], unknownFields };
}

/** The parser-module contract: `@ti/parsers/<name>` exports `parse`. */
export const parse = parseAiaaicRow;
