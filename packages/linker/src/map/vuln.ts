import { isCve } from '@ti/core/ids';
import type { VulnKind, VulnRecord } from '@ti/core/types';
import { cutSummary, cvssScore, isoDate, jsonList, readList, text, vulnId } from '../clean';
import type { VulnDraft } from '../draft';
import { CVE_HOME_SOURCE } from '../tables';

const VULN_KINDS: ReadonlySet<string> = new Set<VulnKind>(['cve', 'ghsa', 'osv', 'mal', 'euvd', 'other']);

const isEmpty = (d: VulnDraft, col: string): boolean => {
  const v = d.row[col];
  return v === null || v === undefined || v === '' || (col === 'title' && v === d.key);
};

/** Folds one vulnerability record onto the draft's row. */
export function applyVuln(d: VulnDraft, r: VulnRecord): void {
  const row = d.row;
  const own = vulnId(r.key);
  const cveHub = isCve(d.key);
  const home = cveHub ? r.source === CVE_HOME_SOURCE : own === d.key;

  if (cveHub) row.kind = 'cve';
  else if (own === d.key && VULN_KINDS.has(r.kind)) row.kind = r.kind;

  const title = text(r.title);
  if (title && (home || isEmpty(d, 'title'))) row.title = title;
  const summary = text(r.summary);
  if (summary && (home || isEmpty(d, 'summary'))) row.summary = cutSummary(summary);
  const published = isoDate(r.published);
  if (published && (home || isEmpty(d, 'published'))) row.published = published;

  row.cwe = jsonList([...readList(row.cwe), ...(Array.isArray(r.cwe) ? r.cwe : [])]);

  // CVSS belongs to the scorer that set it first, so two scorers never flip-flop.
  const score = cvssScore(r.cvss);
  if (score !== null) {
    const scorer = text(r.cvssSource) ?? r.source;
    const owner = row.cvss_source;
    if (owner === null || owner === undefined || owner === '' || owner === scorer) {
      row.cvss = score;
      row.cvss_version = text(r.cvssVersion) ?? row.cvss_version ?? null;
      row.cvss_source = scorer;
      d.changeSource.cvss_change = r.source;
    }
  }
}
