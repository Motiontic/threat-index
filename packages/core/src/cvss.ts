/**
 * Which MTI source delivered a vulnerability's CVSS score. Display rules follow this source;
 * `cvss_source` is the scorer's name (CNA, ADP, NVD) and is attribution only.
 *
 * Rows written before `cvss_from` existed have it NULL. The score then came from the NVD record when the
 * scorer is `nvd`. For any other scorer both `cve-list` (CNA, CISA-ADP) and `euvd` (ENISA, which reports the
 * CVE assigner as scorer) could have delivered it, so it is derived as `cve-list` only when `sources` lists
 * `cve-list` and not `enisa`. Anything else is ambiguous and returns null, which callers treat as hidden.
 */
export function cvssDeliveredBy(row: {
  cvss_from?: string | null;
  cvss_source: string | null;
  sources?: string | readonly string[] | null;
}): string | null {
  if (row.cvss_from) return row.cvss_from;
  if (!row.cvss_source) return null;
  if (row.cvss_source.toLowerCase() === 'nvd') return 'nvd';
  const list = sourceList(row.sources);
  return list.includes('cve-list') && !list.includes('enisa') ? 'cve-list' : null;
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
