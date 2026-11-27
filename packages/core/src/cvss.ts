/**
 * Which MTI source delivered a vulnerability's CVSS score. Display rules follow this source;
 * `cvss_source` is the scorer's name (CNA, ADP, NVD) and is attribution only.
 *
 * Rows written before `cvss_from` existed have it NULL. The score then came from the NVD record when the
 * scorer is `nvd`, and otherwise from the `cve-list` record (CNA and CISA-ADP scores live there).
 */
export function cvssDeliveredBy(row: {
  cvss_from?: string | null;
  cvss_source: string | null;
}): string | null {
  if (row.cvss_from) return row.cvss_from;
  if (!row.cvss_source) return null;
  return row.cvss_source.toLowerCase() === 'nvd' ? 'nvd' : 'cve-list';
}
