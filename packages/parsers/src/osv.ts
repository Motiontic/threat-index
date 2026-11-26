import { isCve, normaliseId } from '@ti/core/ids';
import type {
  AdvisoryRecord,
  Affected,
  ParsedRecord,
  ParseResult,
  RangeType,
  VulnRecord,
} from '@ti/core/types';

/**
 * OSV parser (https://ossf.github.io/osv-schema/). One parser serves OSV.dev, the GitHub Advisory
 * Database, Debian and Ubuntu; a profile names the source and says which records it keeps.
 * No Node-only imports: the same code runs in Workers and E2B.
 */

export interface OsvProfile {
  /** Written into every record's `source`. */
  source: string;
  /** Whether this profile keeps a record. `ecosystems` are base names (text before the first ':'). */
  keep(id: string, ecosystems: readonly string[]): boolean;
}

export const MAX_AFFECTED = 200;

/** Language package ecosystems the `osv` source keeps. */
export const LANGUAGE_ECOSYSTEMS: ReadonlySet<string> = new Set([
  'npm',
  'PyPI',
  'Go',
  'crates.io',
  'Maven',
  'NuGet',
  'RubyGems',
  'Packagist',
  'Pub',
  'Hex',
  'Hackage',
  'GHC',
  'CRAN',
  'Julia',
  'SwiftURL',
  'GitHub Actions',
  'OSS-Fuzz',
  'opam',
  'VSCode',
]);

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;
const CWE = /^CWE-\d+$/;
const MAX_VERSIONS = 20;
const MAX_EXACT_VERSIONS = 1000;

const KNOWN_TOP = new Set([
  'schema_version',
  'id',
  'modified',
  'published',
  'withdrawn',
  'aliases',
  'upstream',
  'related',
  'summary',
  'details',
  'severity',
  'affected',
  'references',
  'credits',
  'database_specific',
]);
const KNOWN_AFFECTED = new Set([
  'package',
  'severity',
  'ranges',
  'versions',
  'ecosystem_specific',
  'database_specific',
]);
const KNOWN_RANGE = new Set(['type', 'repo', 'events', 'database_specific']);
const KNOWN_EVENT = new Set(['introduced', 'fixed', 'last_affected', 'limit']);

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

const TIME = /^(\d{4}-\d{2}-\d{2})[Tt](\d{2}:\d{2}:\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

/** RFC 3339 -> UTC `YYYY-MM-DDTHH:MM:SS.sssZ`, fraction truncated (not rounded) to milliseconds. */
function toIso(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const m = TIME.exec(v.trim());
  if (!m) return undefined;
  const ms = (m[3] ?? '').slice(0, 3).padEnd(3, '0');
  const zone = (m[4] as string).toUpperCase();
  const t = Date.parse(`${m[1]}T${m[2]}.${ms}${zone}`);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}

function cut(s: string, max: number, ellipsis: boolean): string {
  if (s.length <= max) return s;
  const keep = ellipsis ? max - 1 : max;
  let out = s.slice(0, keep);
  const last = out.charCodeAt(out.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1);
  return ellipsis ? `${out}…` : out;
}

interface Unwrapped {
  osv: unknown;
  /** Text before the first '/' of a ChangeItem ref. */
  refEcosystem?: string;
}

/** Accepts a ChangeItem, a GitFile, a JSON string or a parsed OSV object. null = nothing to parse. */
function unwrap(input: unknown): Unwrapped | null {
  let value = input;
  let refEcosystem: string | undefined;
  if (isObj(value) && !('id' in value) && 'text' in value) {
    if (value.status === 'removed') return null;
    if (typeof value.ref === 'string' && value.ref.includes('/')) {
      refEcosystem = value.ref.slice(0, value.ref.indexOf('/'));
    }
    value = value.text;
    if (value === null || value === undefined) return null;
  }
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (err) {
      throw new Error('osv: invalid JSON', { cause: err });
    }
  }
  return { osv: value, refEcosystem };
}

function versionsEntry(ecosystem: string, name: string, versions: string[]): Affected {
  const shown = versions.slice(0, MAX_VERSIONS).join(', ');
  const more = versions.length - MAX_VERSIONS;
  return { ecosystem, name, range: more > 0 ? `${shown} (+${more} more)` : shown };
}

function pairsOf(range: Obj, type: RangeType, ecosystem: string, name: string): Affected[] {
  const out: Affected[] = [];
  let open: Affected | null = null;
  const start = (): Affected => ({ ecosystem, name, rangeType: type });
  const close = () => {
    if (open) out.push(open);
    open = null;
  };
  for (const ev of Array.isArray(range.events) ? range.events : []) {
    if (!isObj(ev)) continue;
    const introduced = str(ev.introduced);
    const fixed = str(ev.fixed);
    const last = str(ev.last_affected);
    if (introduced !== undefined) {
      close();
      open = start();
      if (introduced !== '0') open.introduced = introduced;
    } else if (fixed !== undefined) {
      const pair: Affected = open ?? start();
      pair.fixed = fixed;
      out.push(pair);
      open = null;
    } else if (last !== undefined) {
      const pair: Affected = open ?? start();
      pair.range = `<= ${last}`;
      pair.lastAffected = last;
      out.push(pair);
      open = null;
    }
    // `limit` is ignored.
  }
  close();
  return out;
}

function affectedOf(osv: Obj): Affected[] {
  const out: Affected[] = [];
  const seen = new Set<string>();
  const add = (a: Affected) => {
    if (out.length >= MAX_AFFECTED) return;
    const key = JSON.stringify([
      a.ecosystem,
      a.name,
      a.introduced,
      a.fixed,
      a.range,
      a.rangeType,
      a.lastAffected,
      a.versions,
    ]);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(a);
  };
  for (const entry of Array.isArray(osv.affected) ? osv.affected : []) {
    if (out.length >= MAX_AFFECTED) break;
    if (!isObj(entry) || !isObj(entry.package)) continue;
    const name = str(entry.package.name);
    const ecosystem = str(entry.package.ecosystem);
    if (!name || !ecosystem) continue;
    const pairs: Affected[] = [];
    for (const r of Array.isArray(entry.ranges) ? entry.ranges : []) {
      if (isObj(r) && (r.type === 'SEMVER' || r.type === 'ECOSYSTEM'))
        pairs.push(...pairsOf(r, r.type, ecosystem, name));
    }
    if (pairs.length > 0) {
      // A bare `introduced: "0"` pair is kept: it means every version. A list next to a range adds nothing.
      for (const p of pairs) add(p);
      continue;
    }
    const versions = strings(entry.versions);
    if (versions.length === 0) continue;
    const display = versionsEntry(ecosystem, name, versions);
    if (versions.length <= MAX_EXACT_VERSIONS) {
      display.rangeType = 'EXACT';
      display.versions = versions;
    }
    add(display);
  }
  return out;
}

function unknownFieldsOf(osv: Obj): string[] {
  const unknown = new Set<string>();
  for (const k of Object.keys(osv)) if (!KNOWN_TOP.has(k)) unknown.add(k);
  for (const entry of Array.isArray(osv.affected) ? osv.affected : []) {
    if (!isObj(entry)) continue;
    for (const k of Object.keys(entry)) if (!KNOWN_AFFECTED.has(k)) unknown.add(`affected.${k}`);
    for (const r of Array.isArray(entry.ranges) ? entry.ranges : []) {
      if (!isObj(r)) continue;
      for (const k of Object.keys(r)) if (!KNOWN_RANGE.has(k)) unknown.add(`affected.ranges.${k}`);
      for (const ev of Array.isArray(r.events) ? r.events : []) {
        if (!isObj(ev)) continue;
        for (const k of Object.keys(ev)) if (!KNOWN_EVENT.has(k)) unknown.add(`affected.ranges.events.${k}`);
      }
    }
  }
  return [...unknown];
}

function ecosystemsOf(osv: Obj, refEcosystem: string | undefined): string[] {
  const out = new Set<string>();
  for (const entry of Array.isArray(osv.affected) ? osv.affected : []) {
    const eco = isObj(entry) && isObj(entry.package) ? str(entry.package.ecosystem) : undefined;
    if (eco) out.add(eco.slice(0, eco.indexOf(':') === -1 ? undefined : eco.indexOf(':')));
  }
  if (refEcosystem) out.add(refEcosystem);
  return [...out];
}

function urlOf(id: string, osv: Obj): string {
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
  for (const ref of Array.isArray(osv.references) ? osv.references : []) {
    if (isObj(ref) && ref.type === 'ADVISORY') {
      const u = str(ref.url);
      if (u && /^https?:\/\//i.test(u)) return u;
    }
  }
  return `https://osv.dev/vulnerability/${id}`;
}

function cweOf(osv: Obj): string[] {
  const db = isObj(osv.database_specific) ? osv.database_specific : {};
  const raw = [...strings(db.cwe_ids)];
  // Malicious-package records carry `cwes` on each affected entry rather than on the record.
  const dbs = [db];
  for (const a of Array.isArray(osv.affected) ? osv.affected : []) {
    if (isObj(a) && isObj(a.database_specific)) dbs.push(a.database_specific);
  }
  for (const d of dbs) {
    if (Array.isArray(d.cwes))
      for (const c of d.cwes) if (isObj(c) && typeof c.cweId === 'string') raw.push(c.cweId);
  }
  return [...new Set(raw.filter((c) => CWE.test(c)))];
}

/** The record's summary text: `summary`, else the first 2,000 characters of `details`; collapsed, cut to 300. */
function summaryOf(osv: Obj): string {
  const summary = str(osv.summary)?.trim();
  const details = str(osv.details);
  const body = (summary ?? details?.slice(0, 2000) ?? '').replace(/\s+/g, ' ').trim();
  return cut(body, 300, true);
}

/** One-word `database_specific.severity` (GHSA), else an Ubuntu `severity[]` score; upper-cased, at most 16. */
function severityOf(osv: Obj, db: Obj): string | undefined {
  let label: string | undefined;
  const dbSev = str(db.severity);
  if (dbSev && /^\S+$/.test(dbSev.trim())) label = dbSev.trim();
  if (!label && Array.isArray(osv.severity)) {
    for (const s of osv.severity) {
      if (isObj(s) && s.type === 'Ubuntu') {
        const score = str(s.score)?.trim();
        if (score && /^\S+$/.test(score)) {
          label = score;
          break;
        }
      }
    }
  }
  if (!label) return undefined;
  return label.toUpperCase().slice(0, 16);
}

/** True only when fix versions come from the ecosystem's own vulnerability database or a reviewed advisory. */
export function reviewedFix(source: string, id: string, databaseSpecific: Record<string, unknown>): boolean {
  switch (source) {
    case 'github-advisory-db':
      return databaseSpecific.github_reviewed === true;
    case 'osv':
      if (id.startsWith('PYSEC-') || id.startsWith('RUSTSEC-')) return true;
      return id.startsWith('GO-') && databaseSpecific.review_status === 'REVIEWED';
    case 'debian':
    case 'ubuntu':
      return true;
    default:
      return false;
  }
}

export function parseOsv(input: unknown, profile: OsvProfile): ParseResult<VulnRecord | AdvisoryRecord> {
  const empty = { records: [], unknownFields: [] };
  const un = unwrap(input);
  if (!un) return empty;
  const osv = un.osv;
  if (!isObj(osv)) throw new Error('osv: record is not an object');
  const rawId = osv.id;
  if (typeof rawId !== 'string' || !SAFE_ID.test(rawId)) throw new Error('osv: missing or unsafe id');
  const modified = toIso(osv.modified);
  if (!modified) throw new Error(`osv: ${rawId}: missing or invalid modified`);
  const id = normaliseId(rawId);

  if (!profile.keep(id, ecosystemsOf(osv, un.refEcosystem))) return empty;

  const published = toIso(osv.published);
  const aliases = [...strings(osv.aliases), ...strings(osv.upstream)].map(normaliseId);
  const cve = strings(osv.aliases).find(isCve) ?? strings(osv.upstream).find(isCve);
  const vulnKey = cve ? normaliseId(cve) : null;
  const withdrawn = osv.withdrawn !== undefined && osv.withdrawn !== null && osv.withdrawn !== '';

  const summaryText = summaryOf(osv);
  const dbSpecific = isObj(osv.database_specific) ? osv.database_specific : {};
  const advisory: AdvisoryRecord = {
    source: profile.source,
    sourceId: id,
    vulnKey,
    status: withdrawn ? 'withdrawn' : 'active',
    modified,
    url: urlOf(id, osv),
    affected: affectedOf(osv),
    reviewed: reviewedFix(profile.source, id, dbSpecific),
  };
  if (published) advisory.published = published;
  if (summaryText) advisory.summary = summaryText;
  const severity = severityOf(osv, dbSpecific);
  if (severity) advisory.severity = severity;

  const records: (VulnRecord | AdvisoryRecord)[] = [];
  if (vulnKey === null && !withdrawn) {
    const summary = str(osv.summary)?.trim();
    const details = str(osv.details);
    const firstLine = details
      ?.split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.length > 0);
    const vuln: VulnRecord = {
      key: id,
      kind: id.startsWith('MAL-') ? 'mal' : id.startsWith('GHSA-') ? 'ghsa' : 'osv',
      title: cut(summary || firstLine || id, 200, false),
      summary: summaryText,
      modified,
      cwe: cweOf(osv),
      aliases: [...new Set(aliases)].filter((a) => a !== id),
      source: profile.source,
    };
    if (published) vuln.published = published;
    records.push(vuln);
  }
  records.push(advisory);
  return { records, unknownFields: unknownFieldsOf(osv) };
}

/**
 * The `osv` source: OSV.dev's language-package records. GHSA ids belong to `github-advisory-db`, and
 * Linux distributions, container images and vendor feeds (Debian, Ubuntu, Red Hat, Alpine, SUSE, Docker
 * Hardened Images…) have their own sources and licence statuses, or none yet.
 */
const OSV_PROFILE: OsvProfile = {
  source: 'osv',
  keep: (id, ecosystems) =>
    !id.startsWith('GHSA-') && ecosystems.length > 0 && ecosystems.every((e) => LANGUAGE_ECOSYSTEMS.has(e)),
};

export function parse(input: unknown): ParseResult<ParsedRecord> {
  return parseOsv(input, OSV_PROFILE);
}
