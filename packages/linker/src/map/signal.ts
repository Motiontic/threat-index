import type { SignalRecord } from '@ti/core/types';
import { httpUrl } from '../clean';
import { earliest, type VulnDraft } from '../draft';
import { KEV_SOURCE, type Row } from '../tables';

export function signalRow(hub: string, r: SignalRecord): Row {
  return {
    vuln_key: hub,
    kind: r.kind,
    source: r.source,
    ref: r.ref,
    first_seen: r.firstSeen,
    evidence_date: typeof r.evidenceDate === 'string' ? r.evidenceDate : null,
    url: httpUrl(r.url),
  };
}

/** The `vulns` columns a signal sets. `poc`, `detection` and other sources' `exploited_wild` set none. */
export function applySignal(d: VulnDraft, r: SignalRecord): void {
  const row = d.row;
  if (r.kind === 'exploited_wild' && r.source === KEV_SOURCE) {
    row.kev_added = earliest(row.kev_added, r.firstSeen);
    d.changeSource.newly_exploited ??= r.source;
  } else if (r.kind === 'ransomware') {
    row.ransomware = 1;
  } else if (r.kind === 'public_exploit') {
    row.exploit_public = 1;
    d.changeSource.public_exploit ??= r.source;
    d.exploitAt = earliest(d.exploitAt, r.firstSeen);
  }
}
