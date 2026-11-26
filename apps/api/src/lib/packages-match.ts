/**
 * Matching and upgrade advice for POST /v1/packages/check. Pure code. Version rules come in as a dependency
 * so tests can pass a toy comparer.
 */

import type { Ecosystem, Priority } from '@ti/core/packages';
import { type Comparer, comparerFor, inRange, type RangeRow } from '@ti/core/versions';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { baseEcosystem, validVersion } from './packages-input';
import type { AffectedRecordRow } from './packages-lookup';

export interface VersionRules {
  inRange: typeof inRange;
  comparerFor: typeof comparerFor;
}
export const DEFAULT_RULES: VersionRules = { inRange, comparerFor };

export const MAX_MATCHES_PER_PACKAGE = 50;
export const PRIORITY_ORDER: readonly Priority[] = ['fix_now', 'fix_soon', 'plan', 'note'];
export const priorityRank = (p: Priority): number => PRIORITY_ORDER.indexOf(p);

export const MALICIOUS_SOURCE = 'openssf-malicious-packages';

/** An OSV key such as "Debian:12" compares by its base ecosystem. */
const comparerOf = (rules: VersionRules, ecosystem: string): Comparer | null =>
  rules.comparerFor(baseEcosystem(ecosystem) as Ecosystem);

/**
 * Whether one `affected` row covers a version. A range row that starts at 0 and has no end covers every
 * version without a comparer (malicious-package records usually look like this).
 */
export function rowCovers(
  ecosystem: string,
  version: string,
  row: RangeRow,
  rules: VersionRules = DEFAULT_RULES,
): boolean | 'unsupported' {
  if (
    row.range_type !== 'EXACT' &&
    row.introduced === '0' &&
    row.fixed === null &&
    row.last_affected === null
  ) {
    return true;
  }
  return rules.inRange(baseEcosystem(ecosystem) as Ecosystem, version, row, comparerOf(rules, ecosystem));
}

export const isMaliciousRow = (r: AffectedRecordRow, vulnKind: string | null | undefined): boolean =>
  r.source === MALICIOUS_SOURCE || r.vuln_key.startsWith('MAL-') || vulnKind === 'mal';

// --- notes ---------------------------------------------------------------------------------------

export const NOTE = {
  suggestion: (v: string, source: string, id: string, date: string) =>
    `${v} fixes every match above, according to ${source} (${id}, updated ${date}). Confirm ${v} exists in the registry and isn't brand new before installing it, and check it for breaking changes.`,
  noFix: (id: string) => `No reviewed fix is listed for ${id}.`,
  malicious: (id: string) =>
    `${id} marks this package as malicious. Remove it rather than upgrading, and treat machines that installed it as exposed.`,
  candidateAffected: (v: string) => `${v} is listed as affected too, so no upgrade is suggested.`,
  cantCheck: (v: string, ecosystem: string) =>
    `MTI can't yet check ${v} against every listed range for ${ecosystem}, so no upgrade is suggested.`,
  cantOrder: (ecosystem: string) =>
    `MTI can't yet order ${ecosystem} versions, so it can't pick one version that fixes every match.`,
} as const;

// --- fix versions --------------------------------------------------------------------------------

export interface FixChoice {
  value: string;
  record: Pick<AffectedRecordRow, 'source' | 'source_id' | 'modified'>;
}

/**
 * `fixedIn` for one match: the `fixed` of the covering row, from reviewed full-display records only. Values
 * that fail the version grammar, or that the comparer puts at or below the checked version, are ignored.
 * Several distinct values give the highest by the comparer, or null when there is no comparer.
 */
export function fixedInFor(
  ecosystem: string,
  version: string,
  coveringRows: readonly AffectedRecordRow[],
  rules: VersionRules = DEFAULT_RULES,
): FixChoice | null {
  const comparer = comparerOf(rules, ecosystem);
  const found = new Map<string, FixChoice>();
  for (const row of coveringRows) {
    const f = row.fixed;
    if (f === null || row.reviewed !== 1 || !validVersion(ecosystem, f)) continue;
    if (comparer && (!comparer.valid(f) || comparer.compare(f, version) <= 0)) continue;
    if (!found.has(f)) found.set(f, { value: f, record: row });
  }
  const all = [...found.values()];
  if (all.length === 0) return null;
  if (all.length === 1) return all[0] as FixChoice;
  if (!comparer) return null;
  return all.reduce((a, b) => (comparer.compare(b.value, a.value) > 0 ? b : a));
}

export interface UpgradeMatch {
  id: string;
  malicious: boolean;
  fix: FixChoice | null;
}

/**
 * `upgradeTo` and its note for one package. `allRows` is every active row of the package from every source,
 * hidden ones included: they never appear in an answer, but they may stop a suggestion.
 */
export function pickUpgrade(
  ecosystem: string,
  version: string,
  matches: readonly UpgradeMatch[],
  allRows: readonly AffectedRecordRow[],
  rules: VersionRules = DEFAULT_RULES,
): { upgradeTo: string | null; upgradeNote: string | null } {
  const none = (upgradeNote: string | null) => ({ upgradeTo: null, upgradeNote });
  if (matches.length === 0) return none(null);
  const unfixed = matches.filter((m) => m.fix === null);
  if (unfixed.length > 0) {
    const bad = unfixed.find((m) => m.malicious) ?? (unfixed[0] as UpgradeMatch);
    return none(bad.malicious ? NOTE.malicious(bad.id) : NOTE.noFix(bad.id));
  }
  const comparer = comparerOf(rules, ecosystem);
  const fixes = matches.map((m) => m.fix as FixChoice);
  const distinct = new Set(fixes.map((f) => f.value));
  let best = fixes[0] as FixChoice;
  if (distinct.size > 1) {
    if (!comparer) return none(NOTE.cantOrder(ecosystem));
    best = fixes.reduce((a, b) => (comparer.compare(b.value, a.value) > 0 ? b : a));
  }
  const candidate = best.value;
  let unsupported = false;
  for (const row of allRows) {
    const covers = rowCovers(ecosystem, candidate, row, rules);
    if (covers === true) return none(NOTE.candidateAffected(candidate));
    if (covers === 'unsupported') unsupported = true;
  }
  if (unsupported) return none(NOTE.cantCheck(candidate, ecosystem));
  const name = SOURCE_BY_ID.get(best.record.source)?.name ?? best.record.source;
  return {
    upgradeTo: candidate,
    upgradeNote: NOTE.suggestion(candidate, name, best.record.source_id, best.record.modified.slice(0, 10)),
  };
}
