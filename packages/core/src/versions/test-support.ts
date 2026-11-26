/** Shared by the versions tests. Not imported by product code. */
import { ECOSYSTEMS, type Ecosystem } from '../packages';
import { comparerFor } from './index';

export interface Vector {
  line: number;
  a: string;
  op: '<' | '=' | '>';
  b: string;
}

/** Parses osv-scalibr's line format. Throws on a malformed line, so a broken file fails loudly. */
export function parseVectors(text: string): Vector[] {
  const out: Vector[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line.trim() === '' || line.startsWith('# ') || line.startsWith('// ')) continue;
    const parts = line.split(' ');
    const op = parts[1];
    if (parts.length !== 3 || !(op === '<' || op === '=' || op === '>') || !parts[0] || !parts[2]) {
      throw new Error(`malformed vector at line ${i + 1}: ${JSON.stringify(line)}`);
    }
    out.push({ line: i + 1, a: parts[0], op, b: parts[2] });
  }
  return out;
}

const SEMVER_FAMILY: Ecosystem[] = ['npm', 'crates.io', 'Go', 'Hex', 'SwiftURL', 'GitHub Actions'];

/** Every vector file under `fixtures/versions/`, and the ecosystems it applies to. */
export const VECTOR_FILES: Readonly<Record<string, readonly Ecosystem[]>> = {
  'osv-scalibr/semver-versions.txt': SEMVER_FAMILY,
  'standards/semver-org.txt': [...SEMVER_FAMILY, 'NuGet'],
  'osv-scalibr/pub-versions.txt': ['Pub'],
  'osv-scalibr/nuget-versions.txt': ['NuGet'],
  'mti/nuget.txt': ['NuGet'],
  'osv-scalibr/pypi-versions.txt': ['PyPI'],
  'osv-scalibr/pypi-versions-generated.txt': ['PyPI'],
  'standards/pep440.txt': ['PyPI'],
  'osv-scalibr/maven-versions.txt': ['Maven'],
  'osv-scalibr/maven-versions-generated.txt': ['Maven'],
  'osv-dev/maven.txt': ['Maven'],
  'mti/maven.txt': ['Maven'],
  'osv-scalibr/rubygems-versions.txt': ['RubyGems'],
  'osv-scalibr/rubygems-versions-generated.txt': ['RubyGems'],
  'osv-scalibr/packagist-versions.txt': ['Packagist'],
  'osv-scalibr/packagist-versions-generated.txt': ['Packagist'],
  'mti/packagist.txt': ['Packagist'],
  'osv-scalibr/debian-versions.txt': ['Debian', 'Ubuntu'],
  'osv-scalibr/debian-versions-generated.txt': ['Debian', 'Ubuntu'],
  'mti/dpkg.txt': ['Debian', 'Ubuntu'],
  'osv-scalibr/alpine-versions.txt': ['Alpine'],
  'osv-scalibr/alpine-versions-generated.txt': ['Alpine'],
  'mti/alpine.txt': ['Alpine'],
  'osv-scalibr/redhat-versions.txt': ['Red Hat'],
  'mti/rpm.txt': ['Red Hat'],
  'mti/go.txt': ['Go'],
  'mti/github-actions.txt': ['GitHub Actions'],
};

interface GlobImportMeta {
  glob(
    pattern: string | string[],
    options: { query: string; import: string; eager: true },
  ): Record<string, string>;
}

/** Strips the glob's relative prefix: `osv-scalibr/semver-versions.txt`. */
export const fixturePath = (key: string): string =>
  key.slice(key.indexOf('fixtures/versions/') + 'fixtures/versions/'.length);

/** The small vector files only (no `*-generated.txt`), so the Workers bundle stays small. */
export const SMALL_VECTORS: Record<string, string> = (import.meta as unknown as GlobImportMeta).glob(
  ['../../../../fixtures/versions/*/*.txt', '!../../../../fixtures/versions/*/*-generated.txt'],
  { query: '?raw', import: 'default', eager: true },
);

/** Independent oracles for the few vector versions MTI's `valid()` rejects on purpose. */
const PEP440 =
  /^v?(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:alpha|a|beta|b|preview|pre|c|rc)[-_.]?\d*)?(?:(?:-\d+)|(?:[-_.]?(?:post|rev|r)[-_.]?\d*))?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;
const APK = /^\d+(?:\.\d+)*[a-z]?(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*(?:-r\d+)?$/;
const HAS_DIGIT = /\d/;
const NON_ASCII = /[\u0080-\uFFFF]/;

/**
 * Why a vector version is allowed to be `valid() === false`, or null when it must be valid:
 * - PyPI: legacy strings that old `packaging` accepted (`0.1-bulbasaur`, timestamps); `compare` still orders them;
 * - Alpine: apk accepts malformed strings (`.1`, `1-ruff`, `_blah`) and orders them its own way;
 * - Maven: strings with no digit (`stable`) are not versions, but Maven still orders them;
 * - Red Hat: rpm treats non-ASCII bytes as separators, but the printable-ASCII guard never widens, so
 *   these lines are skipped entirely (`skipsCompare`).
 */
export function exemptionReason(ecosystem: Ecosystem, version: string): string | null {
  if (ecosystem === 'Maven' && !HAS_DIGIT.test(version)) return 'Maven needs a digit to be valid';
  if (ecosystem === 'PyPI' && !PEP440.test(version)) return 'PyPI legacy version';
  if (ecosystem === 'Alpine' && !APK.test(version)) return 'apk accepts malformed strings';
  if (ecosystem === 'Red Hat' && NON_ASCII.test(version)) return 'non-ASCII is rejected by the guard';
  return null;
}

export interface BenchPair {
  ecosystem: Ecosystem;
  a: string;
  b: string;
  op: '<' | '=' | '>';
}

/** 10,000 items, built by cycling through SMALL_VECTORS for all 16 ecosystems in a fixed order. */
export function benchPairs(count = 10_000): BenchPair[] {
  const byEcosystem = new Map<Ecosystem, BenchPair[]>();
  for (const e of ECOSYSTEMS) byEcosystem.set(e, []);
  for (const path of Object.keys(SMALL_VECTORS).sort()) {
    const mapped = VECTOR_FILES[fixturePath(path)];
    if (!mapped) continue;
    for (const v of parseVectors(SMALL_VECTORS[path] as string)) {
      for (const ecosystem of mapped) {
        if (exemptionReason(ecosystem, v.a) || exemptionReason(ecosystem, v.b)) continue;
        byEcosystem.get(ecosystem)?.push({ ecosystem, a: v.a, b: v.b, op: v.op });
      }
    }
  }
  const out: BenchPair[] = [];
  for (let k = 0; k < count; k++) {
    const list = byEcosystem.get(ECOSYSTEMS[k % ECOSYSTEMS.length] as Ecosystem) as BenchPair[];
    out.push(list[Math.floor(k / ECOSYSTEMS.length) % list.length] as BenchPair);
  }
  return out;
}

export const expectedSign = (op: '<' | '=' | '>'): -1 | 0 | 1 => (op === '<' ? -1 : op === '>' ? 1 : 0);

/** Looks up a comparer and fails loudly when it is missing. */
export function mustComparer(e: Ecosystem) {
  const c = comparerFor(e);
  if (!c) throw new Error(`no comparer for ${e}`);
  return c;
}

/** Lines whose order can't hold under the guard: not even the comparison is checked. */
export const skipsCompare = (ecosystem: Ecosystem, version: string): boolean =>
  ecosystem === 'Red Hat' && NON_ASCII.test(version);
