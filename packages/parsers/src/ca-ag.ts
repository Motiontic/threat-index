import type { NoticeRecord, ParseResult } from '@ti/core/types';
import { bodies, cleanName, noteUnknown, usDate } from './notice-us';

const LINK = /^https:\/\/oag\.ca\.gov\/ecrime\/databreach\/reports\/(sb24-\d+)$/;
const KNOWN = new Set(['name', 'link', 'breachDates', 'reported']);

/** California AG breach list rows, as the page pattern yields them. The list gives no count. */
export function parseCaAg(input: unknown): ParseResult<NoticeRecord> & { skipped: number } {
  const records: NoticeRecord[] = [];
  const unknown = new Set<string>();
  let skipped = 0;
  for (const row of bodies(input, 'ca-ag')) {
    noteUnknown(row, KNOWN, unknown);
    const link = typeof row.link === 'string' ? LINK.exec(row.link) : null;
    const rawName = cleanName(row.name);
    if (!link || !rawName) {
      skipped++;
      continue;
    }
    const dates =
      typeof row.breachDates === 'string'
        ? row.breachDates
            .split(',')
            .map(usDate)
            .filter((d): d is string => d !== undefined)
            .sort()
        : [];
    const notified = usDate(row.reported);
    records.push({
      source: 'ca-ag',
      noticeId: link[1] as string,
      rawName,
      ...(dates.length > 0 ? { occurredFrom: dates[0], occurredTo: dates[dates.length - 1] } : {}),
      ...(notified ? { notified } : {}),
      countUnit: 'not_stated',
      jurisdiction: 'US-CA',
      url: row.link as string,
    });
  }
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = parseCaAg;
