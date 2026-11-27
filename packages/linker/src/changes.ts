import type { NoticeRecord } from '@ti/core/types';
import { ageQuiet } from './age';
import { text } from './clean';
import { type Change, detectChanges } from './detect';
import { toVulnState, type VulnDraft } from './draft';
import type { Row } from './tables';

function changeRow(
  c: Change,
  at: string,
  newId: () => string,
  source: string | null,
  eventAt: string | null,
): Row {
  return {
    id: newId(),
    entity_key: c.entityKey,
    kind: c.kind,
    old: c.old,
    new: c.new,
    at,
    source,
    event_at: eventAt,
    quiet: ageQuiet(eventAt, at),
  };
}

/** The date the event happened at the source, per kind. A score change (`cvss_change`) is current: null. */
function eventAtOf(c: Change, d: VulnDraft): string | null {
  switch (c.kind) {
    case 'newly_exploited':
      return c.new;
    case 'public_exploit':
      return d.exploitAt;
    case 'fix_released':
      return d.fixAt;
    default:
      return null;
  }
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
    changeRow(
      c,
      at,
      newId,
      c.kind === 'fix_released' ? d.fixSource : (d.changeSource[c.kind] ?? null),
      eventAtOf(c, d),
    ),
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
    // Never occurredFrom/occurredTo: when a breach happened is not when it became public.
    text(r.notified) ?? text(r.discovered),
  );
}
