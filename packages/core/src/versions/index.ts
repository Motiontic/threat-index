/**
 * Version comparison: one comparer per ecosystem (each in its own file), `comparerFor` to pick one, and
 * `inRange`, which walks an OSV range with it.
 */
import type { Ecosystem } from '../packages';
import { alpine } from './alpine';
import { crates } from './crates';
import { dpkg } from './dpkg';
import { githubActions } from './github-actions';
import { go } from './go';
import { hex } from './hex';
import { maven } from './maven';
import { npm } from './npm';
import { nuget } from './nuget';
import { packagist } from './packagist';
import { pub } from './pub';
import { pypi } from './pypi';
import { rpm } from './rpm';
import { rubygems } from './rubygems';
import { swift } from './swift';

export interface Comparer {
  valid(v: string): boolean;
  compare(a: string, b: string): number;
}

/** A Map, not an object literal: a runtime string such as `constructor` or `__proto__` must give null. */
const COMPARERS: ReadonlyMap<Ecosystem, Comparer> = new Map<Ecosystem, Comparer>([
  ['npm', npm],
  ['PyPI', pypi],
  ['Go', go],
  ['Maven', maven],
  ['crates.io', crates],
  ['RubyGems', rubygems],
  ['NuGet', nuget],
  ['Packagist', packagist],
  ['Hex', hex],
  ['Pub', pub],
  ['SwiftURL', swift],
  ['GitHub Actions', githubActions],
  ['Debian', dpkg],
  ['Ubuntu', dpkg],
  ['Alpine', alpine],
  ['Red Hat', rpm],
]);

/**
 * OS ecosystem keys carry a release exactly as OSV writes them (`Debian:12`, `Ubuntu:22.04:LTS`,
 * `Alpine:v3.20`); those map by prefix. Anything else without a comparer gives null.
 */
export function comparerFor(ecosystem: Ecosystem): Comparer | null {
  const key: unknown = ecosystem;
  if (typeof key !== 'string') return null;
  const exact = COMPARERS.get(key as Ecosystem);
  if (exact) return exact;
  if (key.startsWith('Debian:') || key.startsWith('Ubuntu:')) return dpkg;
  if (key.startsWith('Alpine:')) return alpine;
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
 * EXACT rows match by string equality. An open-ended SEMVER or ECOSYSTEM row (introduced "0", no fixed, no
 * last_affected: every malicious-package record, and distro records with no fix yet) matches any version
 * with no comparer. Other rows use the OSV evaluation rules (introduced, fixed, last_affected; "0" = from
 * the start) with the comparer, and return 'unsupported' when there is none, or when the version or a bound
 * the row uses is not valid for the ecosystem. `comparer` defaults to `comparerFor(ecosystem)`; tests pass
 * a toy one.
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
  if (row.introduced === '0' && row.fixed === null && row.last_affected === null) return true;
  if (comparer === null || !comparer.valid(version)) return 'unsupported';
  const bounds = [row.introduced === '0' ? null : row.introduced, row.fixed, row.last_affected];
  if (bounds.some((b) => b !== null && !comparer.valid(b))) return 'unsupported';
  if (row.introduced !== '0' && comparer.compare(version, row.introduced) < 0) return false;
  if (row.fixed !== null && comparer.compare(version, row.fixed) >= 0) return false;
  if (row.last_affected !== null && comparer.compare(version, row.last_affected) > 0) return false;
  return true;
}
