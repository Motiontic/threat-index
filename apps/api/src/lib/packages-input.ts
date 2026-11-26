/**
 * Input rules for POST /v1/packages/check. Pure code, no bindings.
 *
 * Every entry is checked on its own, so one bad entry never fails the request. A refused entry keeps only
 * `{ index, reason }`: the value is dropped at once and never logged, echoed or stored.
 */
import {
  CheckRequestSchema,
  canonicalEcosystem,
  type Ecosystem,
  MAX_CHECK_PACKAGES,
  normaliseName,
  type PackageRef,
  parsePurl,
  type RejectedEntry,
} from '@ti/core/packages';

export interface CheckEntry {
  index: number;
  ref: PackageRef;
  private: boolean;
}

export type ReadResult =
  | { ok: true; entries: CheckEntry[]; rejected: RejectedEntry[]; needsRelease: boolean }
  | { ok: false; error: 'invalid_body' | 'too_many_packages' };

type Reason = RejectedEntry['reason'];

const RAW_CAPS = { ecosystem: 40, name: 512, version: 256, purl: 1024 } as const;
const MAX_VERSION = 128;

// --- characters ----------------------------------------------------------------------------------

/** Controls and DEL, format (zero-width, bidi, Tag), variation selectors, private-use, unassigned, lone surrogates. */
// biome-ignore lint/suspicious/noMisleadingCharacterClass: variation selectors are rejected on purpose
const BAD_CHARS = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u;

// --- secrets -------------------------------------------------------------------------------------

const CRED_IN_URL = /[^\s/:@]+:[^\s/@]+@/;
const TOKEN_PREFIXES: readonly RegExp[] = [
  /(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}/,
  /(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}/,
  /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}/,
  /(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}/,
  /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,}/,
  /(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}/,
  /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}/,
  /(?<![A-Za-z0-9])pypi-[A-Za-z0-9_-]{50,}/,
];
const LONG_RUN = /[A-Za-z0-9+/=_-]{32,}/g;
const HEX_RUN = /[0-9A-Fa-f]{32,}/g;
const COMMIT_PIN = /^[0-9a-f]{40}$/;

/** Tuned only against the corpora in the tests. */
export const ENTROPY_MIN = 4.3;
export const CHANGES_MIN = 0.3;

export function shannon(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Changes between upper case, lower case and digit, per character. Other characters are skipped. */
export function caseChanges(s: string): number {
  let prev = '';
  let changes = 0;
  for (const ch of s) {
    const k = /[A-Z]/.test(ch) ? 'U' : /[a-z]/.test(ch) ? 'L' : /[0-9]/.test(ch) ? 'D' : '';
    if (!k) continue;
    if (prev && k !== prev) changes++;
    prev = k;
  }
  return changes / s.length;
}

/**
 * True when the string looks like a credential. `purl` relaxes the commit-pin exception to a 40-digit
 * run right after "@", which is where a purl keeps its version.
 */
export function looksLikeSecret(s: string, purl = false): boolean {
  if (CRED_IN_URL.test(s)) return true;
  if (TOKEN_PREFIXES.some((re) => re.test(s))) return true;
  for (const m of s.matchAll(LONG_RUN)) {
    if (shannon(m[0]) >= ENTROPY_MIN && caseChanges(m[0]) >= CHANGES_MIN) return true;
  }
  for (const m of s.matchAll(HEX_RUN)) {
    const run = m[0];
    const pin = purl
      ? run.length === 40 && COMMIT_PIN.test(run) && s[(m.index ?? 0) - 1] === '@'
      : COMMIT_PIN.test(s) && run === s;
    if (!pin) return true;
  }
  return false;
}

function decoded(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// --- grammars ------------------------------------------------------------------------------------

/** Names, checked after `normaliseName`. Written without nested quantifiers so a miss can't backtrack badly. */
const NAME_GRAMMAR: Record<string, { re: RegExp; max: number }> = {
  npm: { re: /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/, max: 214 },
  PyPI: { re: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/, max: 214 },
  'crates.io': { re: /^[a-z][a-z0-9-]{0,63}$/, max: 64 },
  Go: { re: /^(?:stdlib|toolchain|[a-z0-9.-]+\.[a-z0-9.-]+(?:\/[A-Za-z0-9._~+-]+)*)$/, max: 256 },
  Maven: { re: /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/, max: 256 },
  RubyGems: { re: /^[A-Za-z0-9_.-]+$/, max: 214 },
  NuGet: { re: /^[a-z0-9_.-]+$/, max: 214 },
  // Equivalent to the published grammar, with `x([sep]?y+)*` rewritten as `y+(sep y+)*`.
  Packagist: {
    re: /^[a-z0-9]+(?:[_.-][a-z0-9]+)*\/[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*$/,
    max: 214,
  },
  Hex: { re: /^[a-z][a-z0-9_]*$/, max: 214 },
  Pub: { re: /^[a-z_][a-z0-9_]*$/, max: 214 },
  SwiftURL: { re: /^[a-z0-9.-]+\.[a-z]{2,}(?:\/[A-Za-z0-9._~-]+)+$/, max: 256 },
  'GitHub Actions': { re: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_./-]+)?$/, max: 256 },
  Debian: { re: /^[a-z0-9][a-z0-9.+-]+$/, max: 214 },
  Ubuntu: { re: /^[a-z0-9][a-z0-9.+-]+$/, max: 214 },
  Alpine: { re: /^[A-Za-z0-9][A-Za-z0-9._+-]*$/, max: 214 },
  'Red Hat': { re: /^[A-Za-z0-9][A-Za-z0-9._+-]*$/, max: 214 },
};

// SemVer 2.0.0, the expression published on semver.org.
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
// PEP 440 Appendix B VERSION_PATTERN, anchored, case-insensitive.
const PEP440 =
  /^\s*v?(?:(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:alpha|a|beta|b|preview|pre|c|rc)[-_.]?[0-9]*)?(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?(?:[-_.]?dev[-_.]?[0-9]*)?)(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$/i;
const GENERIC = /^[A-Za-z0-9][A-Za-z0-9._+~-]*$/;

const VERSION_GRAMMAR: Record<string, RegExp> = {
  npm: SEMVER,
  'crates.io': SEMVER,
  Hex: SEMVER,
  Pub: SEMVER,
  SwiftURL: SEMVER,
  Go: SEMVER,
  PyPI: PEP440,
  NuGet: /^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
  RubyGems: /^\d+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z_.-]+)?$/,
  Debian: /^(?:\d+:)?\d[A-Za-z0-9.+~-]*$/,
  Ubuntu: /^(?:\d+:)?\d[A-Za-z0-9.+~-]*$/,
  'Red Hat': /^(?:\d+:)?[A-Za-z0-9][A-Za-z0-9._+~^-]*$/,
  Maven: GENERIC,
  Packagist: GENERIC,
  'GitHub Actions': GENERIC,
  Alpine: GENERIC,
};

/** Whether `v` is a well-formed version for the ecosystem (Go: without its leading "v"; OS keys allowed). */
export function validVersion(ecosystem: string, v: string): boolean {
  const re = VERSION_GRAMMAR[baseEcosystem(ecosystem)];
  return Boolean(re) && v.length > 0 && v.length <= MAX_VERSION && (re as RegExp).test(v);
}

// --- OS ecosystems -------------------------------------------------------------------------------

const OS_BASES: Record<string, 'Debian' | 'Ubuntu' | 'Alpine'> = {
  debian: 'Debian',
  ubuntu: 'Ubuntu',
  alpine: 'Alpine',
};
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,29}$/;

/** "Debian:12" → "Debian". Every other ecosystem is its own base. */
export function baseEcosystem(key: string): string {
  const i = key.indexOf(':');
  return i > 0 ? key.slice(0, i) : key;
}

/** The release-keyed form OSV writes: Debian:12, Ubuntu:22.04:LTS, Alpine:v3.20. Null when malformed. */
function osKey(base: 'Debian' | 'Ubuntu' | 'Alpine', release: string): string | null {
  if (!RELEASE.test(release)) return null;
  let r = release;
  if (base === 'Alpine' && /^\d/.test(r)) r = `v${r}`;
  if (base === 'Ubuntu' && /^\d\d\.04$/.test(r) && Number(r.slice(0, 2)) % 2 === 0) r = `${r}:LTS`;
  return `${base}:${r}`;
}

/** Null when the key is neither canonical nor a release-keyed OS ecosystem. `needsRelease` for bare Debian/Ubuntu. */
function resolveEcosystem(raw: string): { key: string } | { needsRelease: true } | null {
  const canon = canonicalEcosystem(raw);
  if (canon === 'Debian' || canon === 'Ubuntu') return { needsRelease: true };
  if (canon) return { key: canon };
  const i = raw.indexOf(':');
  if (i < 1) return null;
  const base = OS_BASES[raw.slice(0, i).trim().toLowerCase()];
  if (!base) return null;
  let rest = raw.slice(i + 1);
  // "Ubuntu:22.04:LTS" and "Ubuntu:Pro:18.04:LTS" are written as OSV keeps them.
  if (base === 'Ubuntu' && /^22\.04:LTS$/i.test(rest)) rest = '22.04';
  const key = osKey(base, rest);
  return key ? { key } : null;
}

// --- entries -------------------------------------------------------------------------------------

type Raw =
  | { kind: 'fields'; ecosystem: string; name: string; version: string; private: boolean }
  | { kind: 'purl'; purl: string; private: boolean };

function readShape(item: unknown): Raw | null {
  if (typeof item !== 'object' || item === null || Array.isArray(item)) return null;
  const o = item as Record<string, unknown>;
  const keys = Object.keys(o);
  if (o.private !== undefined && typeof o.private !== 'boolean') return null;
  const priv = o.private === true;
  const rest = keys.filter((k) => k !== 'private');
  const str = (k: string, max: number): string | null =>
    typeof o[k] === 'string' && (o[k] as string).length <= max ? (o[k] as string) : null;
  if (rest.length === 1 && rest[0] === 'purl') {
    const purl = str('purl', RAW_CAPS.purl);
    return purl === null ? null : { kind: 'purl', purl, private: priv };
  }
  if (rest.length === 3 && ['ecosystem', 'name', 'version'].every((k) => rest.includes(k))) {
    const ecosystem = str('ecosystem', RAW_CAPS.ecosystem);
    const name = str('name', RAW_CAPS.name);
    const version = str('version', RAW_CAPS.version);
    if (ecosystem === null || name === null || version === null) return null;
    return { kind: 'fields', ecosystem, name, version, private: priv };
  }
  return null;
}

/** Steps 2 to 4 on one string. */
function screen(s: string, opts: { purl?: boolean; urlCheck?: boolean } = {}): Reason | null {
  if (BAD_CHARS.test(s)) return 'bad_characters';
  const urlPart = opts.purl ? s.slice(0, firstOf(s, '?#')) : s;
  if (opts.urlCheck !== false && urlPart.includes('://')) return 'looks_like_url';
  if (looksLikeSecret(s, opts.purl)) return 'looks_like_secret';
  if (opts.purl) {
    const d = decoded(s);
    if (d !== s && looksLikeSecret(d, true)) return 'looks_like_secret';
  }
  return null;
}

function firstOf(s: string, chars: string): number {
  for (let i = 0; i < s.length; i++) if (chars.includes(s[i] as string)) return i;
  return s.length;
}

/** Runs one phase over several strings: the first string to fail decides. */
function phase(strings: string[], fn: (s: string) => Reason | null): Reason | null {
  for (const s of strings) {
    const r = fn(s);
    if (r) return r;
  }
  return null;
}

type Checked =
  | { ok: true; ref: PackageRef; needsRelease?: never }
  | { ok: false; reason: Reason; needsRelease?: boolean };

function distroRelease(purl: string): string | null {
  const q = purl.indexOf('?');
  if (q < 0) return null;
  const end = purl.indexOf('#', q);
  for (const pair of purl.slice(q + 1, end < 0 ? undefined : end).split('&')) {
    const eq = pair.indexOf('=');
    if (eq > -1 && pair.slice(0, eq).toLowerCase() === 'distro') {
      const d = decoded(pair.slice(eq + 1)).toLowerCase();
      const dash = d.indexOf('-');
      return dash > 0 ? d.slice(dash + 1) : null;
    }
  }
  return null;
}

function checkEntry(raw: Raw): Checked {
  const strings = raw.kind === 'purl' ? [raw.purl] : [raw.ecosystem, raw.name, raw.version];
  const isPurl = raw.kind === 'purl';
  // 2. characters, 3. URLs, 4. secrets: each step runs over every string before the next one starts.
  let r = phase(strings, (s) => (BAD_CHARS.test(s) ? 'bad_characters' : null));
  if (r) return { ok: false, reason: r };
  r = phase(strings, (s) =>
    s.slice(0, isPurl ? firstOf(s, '?#') : s.length).includes('://') ? 'looks_like_url' : null,
  );
  if (r) return { ok: false, reason: r };
  r = phase(strings, (s) => screen(s, { purl: isPurl, urlCheck: false }));
  if (r) return { ok: false, reason: r };

  let ecosystemKey: string;
  let name: string;
  let version: string;
  if (raw.kind === 'purl') {
    // 5. purl
    const parsed = parsePurl(raw.purl);
    if (!parsed.ok) {
      if (parsed.reason === 'bad_ecosystem') {
        const type = /^pkg:([^/]*)\//i.exec(raw.purl)?.[1]?.toLowerCase();
        return { ok: false, reason: 'bad_ecosystem', needsRelease: type === 'deb' };
      }
      return { ok: false, reason: 'bad_purl' };
    }
    name = parsed.ref.name;
    // For OS packages the purl namespace is the vendor (debian, ubuntu, alpine, redhat), not part of the name.
    if (['Debian', 'Ubuntu', 'Alpine', 'Red Hat'].includes(parsed.ref.ecosystem) && name.includes('/')) {
      name = name.slice(name.lastIndexOf('/') + 1);
    }
    version = parsed.ref.version;
    r = phase([name, version], (s) => screen(s));
    if (r) return { ok: false, reason: r };
    ecosystemKey = parsed.ref.ecosystem;
    if (ecosystemKey === 'Debian' || ecosystemKey === 'Ubuntu' || ecosystemKey === 'Alpine') {
      const rel = distroRelease(raw.purl);
      const key = rel ? osKey(ecosystemKey, rel) : null;
      if (key) ecosystemKey = key;
      else if (ecosystemKey !== 'Alpine') return { ok: false, reason: 'bad_ecosystem', needsRelease: true };
    }
  } else {
    // 6. ecosystem
    const eco = resolveEcosystem(raw.ecosystem);
    if (!eco) return { ok: false, reason: 'bad_ecosystem' };
    if ('needsRelease' in eco) return { ok: false, reason: 'bad_ecosystem', needsRelease: true };
    ecosystemKey = eco.key;
    name = raw.name;
    version = raw.version;
  }

  // 7. name: NFKC, normaliseName, then the grammar as a whole-string match.
  const base = baseEcosystem(ecosystemKey) as Ecosystem;
  const nfkc = name.normalize('NFKC');
  r = screen(nfkc);
  if (r) return { ok: false, reason: r };
  const norm = normaliseName(base, nfkc);
  const grammar = NAME_GRAMMAR[base];
  if (norm === null || !grammar || norm.length > grammar.max || !grammar.re.test(norm)) {
    return { ok: false, reason: 'bad_name' };
  }

  // 8. version
  let v = version;
  if (base === 'Go' && v.startsWith('v')) v = v.slice(1);
  if (!validVersion(base, v)) return { ok: false, reason: 'bad_version' };

  return { ok: true, ref: { ecosystem: ecosystemKey as Ecosystem, name: norm, version: v } };
}

export function readCheckBody(input: unknown): ReadResult {
  const parsed = CheckRequestSchema.safeParse(input);
  if (!parsed.success) {
    const list = (input as { packages?: unknown } | null)?.packages;
    const tooMany =
      typeof input === 'object' &&
      input !== null &&
      Array.isArray(list) &&
      list.length > MAX_CHECK_PACKAGES &&
      Object.keys(input).length === 1;
    return { ok: false, error: tooMany ? 'too_many_packages' : 'invalid_body' };
  }
  if (Object.keys(input as object).length !== 1) return { ok: false, error: 'invalid_body' };

  const entries: CheckEntry[] = [];
  const rejected: RejectedEntry[] = [];
  const seen = new Map<string, CheckEntry>();
  let needsRelease = false;
  parsed.data.packages.forEach((item, index) => {
    const shape = readShape(item);
    if (!shape) {
      rejected.push({ index, reason: 'bad_entry' });
      return;
    }
    const checked = checkEntry(shape);
    if (!checked.ok) {
      rejected.push({ index, reason: checked.reason });
      if (checked.needsRelease) needsRelease = true;
      return;
    }
    const { ref } = checked;
    const key = JSON.stringify([ref.ecosystem, ref.name, ref.version]);
    const first = seen.get(key);
    if (first) {
      if (shape.private) first.private = true;
      rejected.push({ index, reason: 'duplicate' });
      return;
    }
    const entry: CheckEntry = { index, ref, private: shape.private };
    seen.set(key, entry);
    entries.push(entry);
  });
  return { ok: true, entries, rejected, needsRelease };
}
