/**
 * Package contracts shared by the API, the MCP Worker, the linker and tests: ecosystem names, name
 * normalisation, purl parsing, the priority ranking, and the request and answer types of
 * `POST /v1/packages/check`. Pure code; the only dependency is zod.
 */
import { z } from 'zod';

export const ECOSYSTEMS = [
  'npm',
  'PyPI',
  'Go',
  'Maven',
  'crates.io',
  'RubyGems',
  'NuGet',
  'Packagist',
  'Hex',
  'Pub',
  'SwiftURL',
  'GitHub Actions',
  'Debian',
  'Ubuntu',
  'Alpine',
  'Red Hat',
] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

/** Lower-case alias or purl type → canonical OSV name. `deb` is absent on purpose: it needs the distro. */
const ALIASES: Readonly<Record<string, Ecosystem>> = {
  npm: 'npm',
  pypi: 'PyPI',
  pip: 'PyPI',
  go: 'Go',
  golang: 'Go',
  maven: 'Maven',
  'crates.io': 'crates.io',
  crates: 'crates.io',
  cargo: 'crates.io',
  rubygems: 'RubyGems',
  gem: 'RubyGems',
  nuget: 'NuGet',
  packagist: 'Packagist',
  composer: 'Packagist',
  hex: 'Hex',
  pub: 'Pub',
  swifturl: 'SwiftURL',
  swift: 'SwiftURL',
  'github actions': 'GitHub Actions',
  'github-actions': 'GitHub Actions',
  githubactions: 'GitHub Actions',
  github: 'GitHub Actions',
  debian: 'Debian',
  ubuntu: 'Ubuntu',
  alpine: 'Alpine',
  apk: 'Alpine',
  'red hat': 'Red Hat',
  redhat: 'Red Hat',
  rpm: 'Red Hat',
};

/**
 * Lower-cased aliases and purl types → canonical name ("pypi" → "PyPI", "cargo" → "crates.io",
 * "golang" → "Go", "gem" → "RubyGems", "composer" → "Packagist"). "deb" needs the distro qualifier, so it
 * is null here; `parsePurl` resolves it.
 */
export function canonicalEcosystem(raw: string): Ecosystem | null {
  if (typeof raw !== 'string' || raw.length > 40) return null;
  const key = raw.trim().toLowerCase();
  return Object.hasOwn(ALIASES, key) ? (ALIASES[key] as Ecosystem) : null;
}

const MAX_NAME = 300;
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
const BAD_NAME_CHARS = new RegExp('[\\u0000-\\u0020\\u007f-\\u009f\\u2028\\u2029]');

/**
 * Per-ecosystem name rules: npm lower-case (scope kept); PyPI PEP 503 ([-_.]+ → "-", lower-case);
 * crates.io lower-case with "_" → "-"; NuGet, Packagist, Hex, Pub lower-case; Go, Maven (group:artifact),
 * RubyGems, SwiftURL unchanged. Returns null when the name can't be valid for that ecosystem.
 */
export function normaliseName(ecosystem: Ecosystem, name: string): string | null {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAME) return null;
  if (BAD_NAME_CHARS.test(name)) return null;
  switch (ecosystem) {
    case 'npm': {
      const lower = name.toLowerCase();
      if (lower.startsWith('@')) return /^@[^/@]+\/[^/@]+$/.test(lower) ? lower : null;
      return lower.includes('/') || lower.includes('@') ? null : lower;
    }
    case 'PyPI': {
      const n = name.toLowerCase().replace(/[-_.]+/g, '-');
      return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(n) ? n : null;
    }
    case 'crates.io':
      return name.toLowerCase().replace(/_/g, '-');
    case 'NuGet':
    case 'Packagist':
    case 'Hex':
    case 'Pub':
      return name.toLowerCase();
    case 'Maven':
      return /^[^:]+:[^:]+$/.test(name) ? name : null;
    default:
      return name;
  }
}

export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

const MAX_PURL = 1024;
const MAX_VERSION = 128;

function decode(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

/** True for a version string that could be real: 1..128 characters, no whitespace or control characters. */
export function validVersionText(v: string): boolean {
  return typeof v === 'string' && v.length > 0 && v.length <= MAX_VERSION && !BAD_NAME_CHARS.test(v);
}

/**
 * Parses `pkg:<type>/<namespace>/<name>@<version>` (percent-decoded). Ignores qualifiers such as
 * repository_url and download_url entirely: they are never returned and never fetched. The one qualifier
 * read is `distro`, and only to tell Debian from Ubuntu for `pkg:deb`. Reasons are the `RejectedEntry` codes.
 */
export function parsePurl(purl: string): { ok: true; ref: PackageRef } | { ok: false; reason: string } {
  const bad = (reason: string) => ({ ok: false as const, reason });
  if (typeof purl !== 'string' || purl.length === 0 || purl.length > MAX_PURL) return bad('bad_purl');
  if (!/^pkg:/i.test(purl)) return bad('bad_purl');
  let rest = purl.slice(4);
  const hash = rest.indexOf('#');
  if (hash > -1) rest = rest.slice(0, hash);
  let query = '';
  const q = rest.indexOf('?');
  if (q > -1) {
    query = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  rest = rest.replace(/^\/+/, '');
  const slash = rest.indexOf('/');
  if (slash < 1) return bad('bad_purl');
  const type = rest.slice(0, slash).toLowerCase();
  let path = rest.slice(slash + 1);
  // The version follows the last "@" after the last "/" (an npm scope's "@" comes before a "/").
  const at = path.lastIndexOf('@');
  if (at < path.lastIndexOf('/') + 1 || at < 1) return bad('bad_version');
  const versionRaw = path.slice(at + 1);
  path = path.slice(0, at);
  const version = decode(versionRaw);
  if (version === null) return bad('bad_purl');
  if (!validVersionText(version)) return bad('bad_version');
  const parts = path.split('/').map(decode);
  if (parts.some((p) => p === null || p === '')) return bad('bad_purl');
  const segs = parts as string[];
  const name = segs[segs.length - 1] as string;
  const ns = segs.slice(0, -1);

  let ecosystem: Ecosystem | null;
  if (type === 'deb') {
    let distro = '';
    for (const pair of query.split('&')) {
      const eq = pair.indexOf('=');
      if (eq > -1 && pair.slice(0, eq).toLowerCase() === 'distro') distro = decode(pair.slice(eq + 1)) ?? '';
    }
    distro = distro.toLowerCase();
    ecosystem = distro.startsWith('ubuntu') ? 'Ubuntu' : distro.startsWith('debian') ? 'Debian' : null;
    if (!ecosystem) return bad('bad_ecosystem');
  } else {
    ecosystem = canonicalEcosystem(type);
    if (!ecosystem) return bad('bad_ecosystem');
  }
  const full = ecosystem === 'Maven' ? [...ns, name].join(ns.length > 0 ? ':' : '') : [...ns, name].join('/');
  const normalised = normaliseName(ecosystem, full);
  if (!normalised) return bad('bad_name');
  return { ok: true, ref: { ecosystem, name: normalised, version } };
}

export type Priority = 'fix_now' | 'fix_soon' | 'plan' | 'note';

export interface PriorityInput {
  exploitedWild: boolean;
  ransomware: boolean;
  malicious: boolean;
  publicExploit: boolean;
  poc: boolean;
  epss: number | null;
  cvss: number | null;
  severityLabel: string | null;
}

/**
 * fix_now: exploited, ransomware or malicious. fix_soon: public exploit or PoC, or EPSS >= 0.1.
 * plan: CVSS >= 7, or label HIGH/CRITICAL when there is no score. note: everything else.
 */
export function rankPriority(i: PriorityInput): Priority {
  if (i.exploitedWild || i.ransomware || i.malicious) return 'fix_now';
  if (i.publicExploit || i.poc || (i.epss !== null && i.epss >= 0.1)) return 'fix_soon';
  if (i.cvss !== null) return i.cvss >= 7 ? 'plan' : 'note';
  const label = i.severityLabel?.trim().toUpperCase();
  return label === 'HIGH' || label === 'CRITICAL' ? 'plan' : 'note';
}

// --- POST /v1/packages/check ---------------------------------------------------------------------

export const MAX_CHECK_PACKAGES = 1000;

/** One package to check: a purl, or an ecosystem, name and version. */
export const CheckEntrySchema = z.union([
  z.object({ purl: z.string().max(MAX_PURL) }).strict(),
  z
    .object({
      ecosystem: z.string().max(40),
      name: z.string().max(MAX_NAME),
      version: z.string().max(MAX_VERSION),
    })
    .strict(),
]);
export type CheckEntry = z.infer<typeof CheckEntrySchema>;

/**
 * The request body. Entries are left as `unknown` here so one bad entry is reported by its index in
 * `rejected` instead of failing the whole request; parse each with `CheckEntrySchema`.
 */
export const CheckRequestSchema = z.object({
  packages: z.array(z.unknown()).min(1).max(MAX_CHECK_PACKAGES),
});
export interface CheckRequest {
  packages: unknown[];
}

export interface RejectedEntry {
  index: number;
  reason: 'bad_ecosystem' | 'bad_name' | 'bad_version' | 'bad_purl' | 'looks_like_secret' | 'duplicate';
}
export interface CheckMatch {
  id: string;
  title: string | null;
  fixedIn: string | null;
  signals: string[];
  cvss: number | null;
  epss: number | null;
  url: string;
  sources: string[];
}
export interface CheckResult {
  package: PackageRef;
  priority: Priority;
  upgradeTo: string | null;
  upgradeNote: string | null;
  matches: CheckMatch[];
}
export interface CheckResponse {
  asOf: string;
  checked: number;
  matched: number;
  summary: Record<Priority, number>;
  results: CheckResult[];
  noRecord: PackageRef[];
  rejected: RejectedEntry[];
  notes: string[];
}
