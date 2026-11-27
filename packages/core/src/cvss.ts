/**
 * Which MTI sources may have delivered a vulnerability's CVSS score. Display rules follow these sources;
 * `cvss_source` is the scorer's name (CNA, ADP, NVD) and is attribution only.
 *
 * Rows written since `cvss_from` exists name the delivering source exactly. Older rows have it NULL: the score
 * came from the NVD record when the scorer is `nvd`; otherwise any of the score-carrying sources the row lists
 * (`cve-list` for CNA and CISA-ADP scores, `enisa`, which reports the CVE assigner as scorer, and `nvd`, which
 * repeats CNA scores) could have delivered it. A score is shown only when every candidate is visible, so an
 * ambiguous old row never shows a score that a hidden source alone might have delivered. No candidate: hidden.
 */
const SCORE_SOURCES = ['cve-list', 'enisa', 'nvd'] as const;

export interface CvssRow {
  cvss_from?: string | null;
  cvss_source: string | null;
  sources?: string | readonly string[] | null;
}

/** The MTI source IDs that may have delivered the score. Empty when there is no score origin to go on. */
export function cvssCandidates(row: CvssRow): string[] {
  if (row.cvss_from) return [row.cvss_from];
  if (!row.cvss_source) return [];
  if (row.cvss_source.toLowerCase() === 'nvd') return ['nvd'];
  const list = sourceList(row.sources);
  return SCORE_SOURCES.filter((s) => list.includes(s));
}

/** True when the score may be shown: at least one candidate, and every candidate visible. */
export function cvssShown(row: CvssRow, visible: (id: string) => boolean): boolean {
  const c = cvssCandidates(row);
  return c.length > 0 && c.every((id) => visible(id));
}

function sourceList(s: string | readonly string[] | null | undefined): readonly string[] {
  if (Array.isArray(s)) return s;
  if (typeof s !== 'string') return [];
  try {
    const v: unknown = JSON.parse(s);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
