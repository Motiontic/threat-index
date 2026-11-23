import { isCve, normaliseId } from '@ti/core/ids';
import type { ParseResult, SignalRecord } from '@ti/core/types';
import { z } from 'zod';

/**
 * Google Project Zero "0day In the Wild" sheet, tab "All", one CSV row per call (the fingerprint pattern's
 * item body). No stated licence; source marked `ask`.
 */
const Row = z.looseObject({
  CVE: z.unknown(),
  Vendor: z.unknown().optional(),
  Product: z.unknown().optional(),
  Type: z.unknown().optional(),
  Description: z.unknown().optional(),
  'Date Discovered': z.unknown().optional(),
  'Date Patched': z.unknown().optional(),
  Advisory: z.unknown().optional(),
  'Analysis URL': z.unknown().optional(),
  'Root Cause Analysis': z.unknown().optional(),
  'Reported By': z.unknown().optional(),
});

const KNOWN = new Set([
  'CVE',
  'Vendor',
  'Product',
  'Type',
  'Description',
  'Date Discovered',
  'Date Patched',
  'Advisory',
  'Analysis URL',
  'Root Cause Analysis',
  'Reported By',
]);

const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** A `YYYY-MM-DD` cell that is a real date, else null. `???` and empty cells are null. */
function day(cell: unknown): string | null {
  if (typeof cell !== 'string') return null;
  const s = cell.trim();
  if (!DAY.test(s)) return null;
  const d = new Date(`${s}T00:00:00.000Z`);
  if (Number.isNaN(d.getTime())) return null;
  const iso = d.toISOString().slice(0, 10);
  return iso === s ? iso : null;
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

export function parseProjectZeroRow(input: unknown): ParseResult<SignalRecord> {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('project-zero: input is not valid JSON');
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !('CVE' in value)) {
    throw new Error('project-zero: expected a row object with a CVE key');
  }
  const row = Row.parse(value);
  const unknown = new Set<string>();
  for (const key of Object.keys(row)) if (!KNOWN.has(key)) unknown.add(key);

  const cell = typeof row.CVE === 'string' ? row.CVE : '';
  const cves = new Set<string>();
  for (const part of cell.split(/[\s,]+/)) if (part && isCve(part)) cves.add(normaliseId(part));

  const discovered = day(row['Date Discovered']);
  const patched = day(row['Date Patched']);
  const firstSeen = discovered ?? patched;
  const url = httpUrl(row['Analysis URL']) ?? httpUrl(row.Advisory);

  const records: SignalRecord[] = [];
  if (firstSeen) {
    for (const cve of cves) {
      records.push({
        vulnKey: cve,
        kind: 'exploited_wild',
        source: 'project-zero',
        ref: cve,
        firstSeen,
        ...(patched ? { evidenceDate: patched } : {}),
        ...(url ? { url } : {}),
      });
    }
  }
  return { records, unknownFields: [...unknown] };
}

/** The parser-module contract: `@ti/parsers/<name>` exports `parse`. */
export const parse = parseProjectZeroRow;
