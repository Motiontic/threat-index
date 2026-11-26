/**
 * Hot-set rule and change detection. D1 holds only the hot set; the full history lives
 * as Parquet in R2 `lake/`. A cold flaw is promoted the moment it becomes hot.
 */
export const HOT_SINCE = '2024-01-01';
export const EPSS_HOT = 0.1;

export interface HotInput {
  published?: string | null;
  kevAdded?: string | null;
  exploitPublic?: boolean;
  epss?: number | null;
}

export function isHot(v: HotInput): boolean {
  return (
    (!!v.published && v.published >= HOT_SINCE) ||
    !!v.kevAdded ||
    !!v.exploitPublic ||
    (v.epss ?? 0) >= EPSS_HOT
  );
}

/** EPSS bands used for "jumped a band" alerts. */
export function epssBand(score: number): 0 | 1 | 2 | 3 {
  if (score < 0.01) return 0;
  if (score < 0.1) return 1;
  if (score < 0.5) return 2;
  return 3;
}

export type ChangeKind =
  | 'newly_exploited'
  | 'public_exploit'
  | 'epss_band'
  | 'fix_released'
  | 'cvss_change'
  | 'breach_notice'
  | 'new_advisory';

export interface Change {
  kind: ChangeKind;
  entityKey: string;
  old: string | null;
  new: string | null;
}

export interface VulnState {
  key: string;
  kevAdded?: string | null;
  exploitPublic?: boolean;
  epss?: number | null;
  cvss?: number | null;
  fixed?: boolean;
}

/** Only the changes a customer would act on become alerts. */
export function detectChanges(before: VulnState | null, after: VulnState): Change[] {
  const out: Change[] = [];
  const key = after.key;
  if (!before?.kevAdded && after.kevAdded)
    out.push({ kind: 'newly_exploited', entityKey: key, old: null, new: after.kevAdded });
  if (!before?.exploitPublic && after.exploitPublic)
    out.push({ kind: 'public_exploit', entityKey: key, old: 'no', new: 'yes' });
  if (after.epss != null && (before?.epss == null || epssBand(before.epss) !== epssBand(after.epss))) {
    if (before?.epss != null)
      out.push({ kind: 'epss_band', entityKey: key, old: String(before.epss), new: String(after.epss) });
  }
  if (!before?.fixed && after.fixed)
    out.push({ kind: 'fix_released', entityKey: key, old: null, new: 'fixed' });
  if (before?.cvss != null && after.cvss != null && Math.abs(after.cvss - before.cvss) >= 1) {
    out.push({ kind: 'cvss_change', entityKey: key, old: String(before.cvss), new: String(after.cvss) });
  }
  return out;
}
