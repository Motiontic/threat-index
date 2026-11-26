/**
 * Version comparison contract. Each ecosystem's comparer arrives in its own file later; until then
 * `comparerFor` returns null and `inRange` answers 'unsupported' for every ranged row.
 */
import type { Ecosystem } from '../packages';

export interface Comparer {
  valid(v: string): boolean;
  compare(a: string, b: string): number;
}

/** Returns null for every ecosystem in this change; comparers arrive in their own files later. */
export function comparerFor(_ecosystem: Ecosystem): Comparer | null {
  return null;
}

export interface RangeRow {
  range_type: 'SEMVER' | 'ECOSYSTEM' | 'EXACT';
  introduced: string;
  fixed: string | null;
  last_affected: string | null;
  versions: string | null;
}

/**
 * EXACT rows match by string equality. Other rows use the OSV evaluation rules (introduced, fixed,
 * last_affected; "0" = from the start) with the comparer, or return 'unsupported' when there is none.
 * `comparer` defaults to `comparerFor(ecosystem)`; tests pass a toy one.
 */
export function inRange(
  ecosystem: Ecosystem,
  version: string,
  row: RangeRow,
  comparer: Comparer | null = comparerFor(ecosystem),
): boolean | 'unsupported' {
  if (row.range_type === 'EXACT') {
    try {
      const list: unknown = JSON.parse(row.versions ?? '[]');
      return Array.isArray(list) && list.some((v) => v === version);
    } catch {
      return false;
    }
  }
  if (!comparer || !comparer.valid(version)) return 'unsupported';
  const bounds = [row.introduced === '0' ? null : row.introduced, row.fixed, row.last_affected];
  if (bounds.some((b) => b !== null && !comparer.valid(b))) return 'unsupported';
  if (row.introduced !== '0' && comparer.compare(version, row.introduced) < 0) return false;
  if (row.fixed !== null && comparer.compare(version, row.fixed) >= 0) return false;
  if (row.last_affected !== null && comparer.compare(version, row.last_affected) > 0) return false;
  return true;
}
