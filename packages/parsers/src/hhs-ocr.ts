import type { NoticeRecord, ParseResult } from '@ti/core/types';
import { bodies, cleanName, noteUnknown, noticeKey, toCount, usDate } from './notice-us';

const LISTING = 'https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf';
const KNOWN = new Set([
  'name',
  'state',
  'entityType',
  'individuals',
  'submitted',
  'breachType',
  'location',
  'associate',
]);

/** HHS OCR breach portal rows (cases under investigation), as the page pattern yields them. */
export function parseHhsOcr(input: unknown): ParseResult<NoticeRecord> & { skipped: number } {
  const records: NoticeRecord[] = [];
  const unknown = new Set<string>();
  let skipped = 0;
  for (const row of bodies(input, 'hhs-ocr')) {
    noteUnknown(row, KNOWN, unknown);
    const rawName = cleanName(row.name);
    const notified = usDate(row.submitted);
    if (!rawName || !notified) {
      skipped++;
      continue;
    }
    const state = typeof row.state === 'string' ? row.state : '';
    const count = toCount(row.individuals);
    records.push({
      source: 'hhs-ocr',
      noticeId: noticeKey(notified, state, rawName),
      rawName,
      notified,
      ...(count !== undefined
        ? { count, countUnit: 'individuals' as const }
        : { countUnit: 'not_stated' as const }),
      jurisdiction: 'US',
      dataTypes: ['health'],
      url: LISTING,
    });
  }
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = parseHhsOcr;
