import type { AdvisoryRecord } from '@ti/core/types';
import { httpUrl, isoDate, vulnId } from '../clean';
import { ALIAS_SOURCE, type Row } from '../tables';

/**
 * The advisory's row. `modified` is carried from the stored row (empty on insert); the linker stamps it
 * only when another column differs.
 */
export function advisoryRow(hub: string, r: AdvisoryRecord, stored: Row | undefined): Row {
  return {
    source: r.source,
    source_id: vulnId(r.sourceId),
    vuln_key: hub,
    status: r.status,
    published: isoDate(r.published) ?? stored?.published ?? null,
    modified: stored?.modified ?? '',
    url: r.url === undefined ? (stored?.url ?? null) : httpUrl(r.url),
    licence: stored?.licence ?? null,
  };
}

/** `(alias, id) -> hub`, in the advisories table. */
export function aliasRow(id: string, hub: string, now: string, stored?: Row): Row {
  return {
    source: ALIAS_SOURCE,
    source_id: id,
    vuln_key: hub,
    status: 'active',
    published: stored?.published ?? null,
    modified: now,
    url: stored?.url ?? null,
    licence: stored?.licence ?? null,
  };
}
