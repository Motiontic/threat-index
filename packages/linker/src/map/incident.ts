import type { IncidentRecord } from '@ti/core/types';
import { differs, httpUrl, isoDate, jsonList } from '../clean';
import type { Row } from '../tables';

/** The full row, or null when nothing but `modified` would change. */
export function incidentRow(r: IncidentRecord, stored: Row | undefined, now: string): Row | null {
  const row: Row = {
    source: r.source,
    incident_id: r.incidentId,
    kind: r.kind,
    title: r.title,
    date: isoDate(r.date) ?? stored?.date ?? null,
    entities: Array.isArray(r.entities) ? jsonList(r.entities) : (stored?.entities ?? null),
    techniques: Array.isArray(r.techniques) ? jsonList(r.techniques) : (stored?.techniques ?? null),
    url: r.url === undefined ? (stored?.url ?? null) : httpUrl(r.url),
    gated: stored?.gated ?? 0,
    modified: stored?.modified ?? '',
  };
  if (!differs(row, stored)) return null;
  return { ...row, modified: now };
}
