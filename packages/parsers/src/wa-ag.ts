import type { NoticeRecord, ParseResult } from '@ti/core/types';
import { z } from 'zod';
import { bodies, cleanName, isoDay, noticeKey, toCount } from './notice-us';

const str = z.string().optional();
/** Washington AG data breach dataset `sb4j-ca4h`; the 25 columns are listed in fixtures/wa-ag/SOURCE.md. */
const Row = z.looseObject({
  id: z.string().regex(/^\d+$/),
  name: z.string(),
  datestart: str,
  dateend: str,
  dateaware: str,
  datesubmitted: str,
  washingtoniansaffected: str,
});

const KNOWN = new Set([
  'dateaware',
  'datesubmitted',
  'databreachcause',
  'datestart',
  'dateend',
  'name',
  'id',
  'cyberattacktype',
  'washingtoniansaffected',
  'industrytype',
  'businesstype',
  'year',
  'yeartext',
  'washingtoniansaffectedrange',
  'breachlifecyclerange',
  'daystocontainbreach',
  'daystoidentifybreach',
  'daysbreachlifecycle',
  'discoveredinprogress',
  'daysofexposure',
  'dayselapsedbetweenendanddiscovery',
  'endedondaydiscovered',
  'dayselapsedbeforenotification',
  'daysofexposurerange',
  'entitystate',
]);

/** Washington AG breach notices. `washingtoniansaffectedrange` is never read as a count. */
export function parseWaAg(input: unknown): ParseResult<NoticeRecord> & { skipped: number } {
  const records: NoticeRecord[] = [];
  const unknown = new Set<string>();
  let skipped = 0;
  for (const raw of bodies(input, 'wa-ag')) {
    for (const k of Object.keys(raw)) if (!KNOWN.has(k)) unknown.add(k);
    const parsed = Row.safeParse(raw);
    const rawName = parsed.success ? cleanName(parsed.data.name) : undefined;
    if (!parsed.success || !rawName) {
      skipped++;
      continue;
    }
    const r = parsed.data;
    const [occurredFrom, occurredTo, discovered, notified] = [
      r.datestart,
      r.dateend,
      r.dateaware,
      r.datesubmitted,
    ].map(isoDay);
    const count = toCount(r.washingtoniansaffected);
    records.push({
      source: 'wa-ag',
      noticeId: noticeKey(r.id),
      rawName,
      ...(occurredFrom ? { occurredFrom } : {}),
      ...(occurredTo ? { occurredTo } : {}),
      ...(discovered ? { discovered } : {}),
      ...(notified ? { notified } : {}),
      ...(count !== undefined
        ? { count, countUnit: 'state_residents' as const }
        : { countUnit: 'not_stated' as const }),
      jurisdiction: 'US-WA',
      url: `https://data.wa.gov/resource/sb4j-ca4h.json?id=${r.id}`,
    });
  }
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = parseWaAg;
