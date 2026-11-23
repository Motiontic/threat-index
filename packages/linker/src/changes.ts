import type { NoticeRecord } from '@ti/core/types';
import { text } from './clean';
import { type Change, detectChanges } from './detect';
import { toVulnState, type VulnDraft } from './draft';
import type { Row } from './tables';

function changeRow(c: Change, at: string, newId: () => string, source: string | null): Row {
  return { id: newId(), entity_key: c.entityKey, kind: c.kind, old: c.old, new: c.new, at, source };
}

/**
 * Alert rows for a hot flaw. `before` is the stored (or merged) row, or on a promotion the summary (or just
 * the key: a user can watch a cold ID). A first insert that is not a promotion writes none.
 * `epss_band` is never emitted: no record carries an EPSS score.
 */
export function vulnChanges(d: VulnDraft, at: string, newId: () => string): Row[] {
  if (!d.before) return [];
  const after = { ...toVulnState(d.row), fixed: d.fromD1 && d.fixSource !== null };
  return detectChanges(d.before, after).map((c) =>
    changeRow(c, at, newId, c.kind === 'fix_released' ? d.fixSource : (d.changeSource[c.kind] ?? null)),
  );
}

/** A notice not stored before, with a company key somebody can watch. */
export function noticeChange(
  r: NoticeRecord,
  stored: Row | undefined,
  at: string,
  newId: () => string,
): Row | null {
  const company = text(r.companyKey);
  if (stored || !company) return null;
  return changeRow(
    { kind: 'breach_notice', entityKey: company, old: null, new: `${r.source}:${r.noticeId}` },
    at,
    newId,
    r.source,
  );
}
