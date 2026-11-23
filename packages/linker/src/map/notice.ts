import type { NoticeRecord } from '@ti/core/types';
import { count, differs, httpUrl, isoDate, jsonList, text } from '../clean';
import type { Row } from '../tables';

const keep = (v: unknown, stored: unknown) => v ?? stored ?? null;

/** The full row, or null when nothing but `modified` would change. */
export function noticeRow(r: NoticeRecord, stored: Row | undefined, now: string): Row | null {
  const n = count(r.count);
  const row: Row = {
    source: r.source,
    notice_id: r.noticeId,
    company_key: keep(text(r.companyKey), stored?.company_key),
    raw_name: r.rawName,
    occurred_from: keep(isoDate(r.occurredFrom), stored?.occurred_from),
    occurred_to: keep(isoDate(r.occurredTo), stored?.occurred_to),
    discovered: keep(isoDate(r.discovered), stored?.discovered),
    notified: keep(isoDate(r.notified), stored?.notified),
    // A count is taken from the notice, never summed with another.
    count: keep(n, stored?.count),
    count_unit: r.countUnit,
    jurisdiction: keep(text(r.jurisdiction), stored?.jurisdiction),
    data_types: Array.isArray(r.dataTypes) ? jsonList(r.dataTypes) : (stored?.data_types ?? null),
    url: r.url === undefined ? (stored?.url ?? null) : httpUrl(r.url),
    event_key: stored?.event_key ?? null,
    modified: stored?.modified ?? '',
  };
  if (!differs(row, stored)) return null;
  return { ...row, modified: now };
}
