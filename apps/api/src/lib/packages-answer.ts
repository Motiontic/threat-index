/**
 * Builds the answer for POST /v1/packages/check from the looked-up data, applying the licence rules
 * `routes/entries.ts` applies: hidden sources are dropped before matching and appear nowhere; link-only
 * sources show id, source and URL only.
 */

import { cvssCandidates, cvssShown } from '@ti/core/cvss';
import type {
  CheckMatch,
  CheckResponse,
  CheckResult,
  ConfusionWarning,
  MatchSignal,
  PackageRef,
  Priority,
  RejectedEntry,
  UncertainEntry,
} from '@ti/core/packages';
import { rankPriority } from '@ti/core/packages';
import { creditsFor } from './credits';
import type { CheckEntry } from './packages-input';
import type { AffectedRecordRow, HotVulnRow, PackageData } from './packages-lookup';
import {
  DEFAULT_RULES,
  type FixChoice,
  fixedInFor,
  isMaliciousRow,
  MAX_MATCHES_PER_PACKAGE,
  pickUpgrade,
  priorityRank,
  rowCovers,
  type VersionRules,
} from './packages-match';

export const DEFAULT_ORIGIN = 'https://mti.motiontic.com';

export const NOTES = {
  noRecord: 'No record means none in MTI as of asOf. It does not mean safe.',
  reachability: "Reachability isn't checked: MTI doesn't know whether your code uses the affected part.",
  fixes:
    "Fix versions come only from reviewed sources. Confirm a release exists and isn't brand new before installing it.",
  uncertain:
    "Some records couldn't be matched to a version yet. They are listed under uncertain, not as matches.",
  private: 'Packages marked private are checked only against public malicious packages with the same name.',
  release:
    'Debian and Ubuntu packages need a release: use ecosystem "Debian:12" or "Ubuntu:22.04", or a purl with a distro qualifier.',
  sources: 'Which sources MTI holds, and how fresh each one is: /sources on the MTI site.',
} as const;

export interface AnswerStats {
  matched: number;
  uncertain: number;
  confusion: number;
  unknownNames: number;
  ecosystems: number;
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 };
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function numericSeverity(s: string | null): number | null {
  if (s === null || !/^\d{1,2}(\.\d+)?$/.test(s.trim())) return null;
  const n = Number(s);
  return n >= 0 && n <= 10 ? n : null;
}

interface Rec {
  source: string;
  source_id: string;
  vuln_key: string;
  rows: AffectedRecordRow[];
}

function groupRecords(rows: readonly AffectedRecordRow[]): Rec[] {
  const out = new Map<string, Rec>();
  for (const r of rows) {
    const k = `${r.source}\u0000${r.source_id}`;
    const rec = out.get(k);
    if (rec) rec.rows.push(r);
    else out.set(k, { source: r.source, source_id: r.source_id, vuln_key: r.vuln_key, rows: [r] });
  }
  return [...out.values()];
}

export interface BuildInput {
  entries: readonly CheckEntry[];
  rejected: readonly RejectedEntry[];
  needsRelease?: boolean;
  data: PackageData;
  now: Date;
  origin?: string | undefined;
  rules?: VersionRules;
}

export function buildAnswer(input: BuildInput): { response: CheckResponse; stats: AnswerStats } {
  const { entries, data, rejected } = input;
  const rules = input.rules ?? DEFAULT_RULES;
  const origin = (input.origin ?? '').replace(/\/+$/, '') || DEFAULT_ORIGIN;
  const mode = (id: string | null) => (id === null ? 'full' : (data.display.get(id) ?? 'hidden'));
  const visible = (id: string | null) => mode(id) !== 'hidden';

  const byPackage = new Map<string, AffectedRecordRow[]>();
  for (const r of data.rows) {
    const k = `${r.ecosystem}\u0000${r.name}`;
    const list = byPackage.get(k);
    if (list) list.push(r);
    else byPackage.set(k, [r]);
  }

  const results: CheckResult[] = [];
  const uncertain: UncertainEntry[] = [];
  const confusion: ConfusionWarning[] = [];
  const noRecord: PackageRef[] = [];
  const usedSources = new Set<string>();
  const ecosystems = new Set<string>();
  let unknownNames = 0;

  for (const entry of entries) {
    const { ref } = entry;
    ecosystems.add(ref.ecosystem);
    const allRows = byPackage.get(`${ref.ecosystem}\u0000${ref.name}`) ?? [];
    if (!entry.private && allRows.length === 0) unknownNames++;
    // Licence first: records from hidden sources are dropped before matching.
    const records = groupRecords(allRows).filter((r) => visible(r.source));

    if (entry.private) {
      const ids = [
        ...new Set(
          records
            .filter((r) => r.rows.some((row) => isMaliciousRow(row, data.vulns.get(row.vuln_key)?.kind)))
            .map((r) => r.vuln_key),
        ),
      ].sort(cmp);
      if (ids.length > 0) {
        for (const r of records) if (ids.includes(r.vuln_key)) usedSources.add(r.source);
        confusion.push({ package: ref, ids, reason: 'public_malicious_name' });
      } else noRecord.push(ref);
      continue;
    }

    const groups = new Map<string, { records: Rec[]; covering: AffectedRecordRow[] }>();
    const uncertainKeys = new Set<string>();
    for (const rec of records) {
      let matched = false;
      let pending = false;
      const covering: AffectedRecordRow[] = [];
      for (const row of rec.rows) {
        const c = rowCovers(ref.ecosystem, ref.version, row, rules);
        if (c === true) {
          matched = true;
          covering.push(row);
        } else if (c === 'unsupported') pending = true;
      }
      if (matched) {
        const g = groups.get(rec.vuln_key) ?? { records: [], covering: [] };
        g.records.push(rec);
        g.covering.push(...covering);
        groups.set(rec.vuln_key, g);
      } else if (pending) uncertainKeys.add(rec.vuln_key);
    }
    for (const k of groups.keys()) uncertainKeys.delete(k);

    const built = [...groups.entries()].map(([key, g]) => {
      const vuln: HotVulnRow | undefined = data.vulns.get(key);
      const sig = (data.signals.get(key) ?? []).filter((s) => visible(s.source));
      const has = (kind: string) => sig.some((s) => s.kind === kind);
      const flags = {
        malicious: g.records.some((r) => r.rows.some((row) => isMaliciousRow(row, vuln?.kind))),
        exploited_wild: Boolean(vuln?.kev_added) || has('exploited_wild'),
        ransomware: vuln?.ransomware === 1 || has('ransomware'),
        public_exploit: vuln?.exploit_public === 1 || has('public_exploit'),
        poc: has('poc'),
      } satisfies Record<MatchSignal, boolean>;
      const signals = (Object.keys(flags) as MatchSignal[]).filter((k) => flags[k]);

      const full = g.records.filter((r) => mode(r.source) === 'full');
      const firstRows = full.map((r) => r.rows[0] as AffectedRecordRow);
      // Shown only when every source that may have delivered the score is visible (an empty list hides it).
      const cvssVisible = vuln && vuln.cvss !== null && cvssShown(vuln, visible) ? vuln.cvss : null;
      const nums = firstRows.map((r) => numericSeverity(r.severity)).filter((n): n is number => n !== null);
      const rankCvss = cvssVisible ?? (nums.length ? Math.max(...nums) : null);
      const labels = firstRows
        .map((r) => (r.severity ?? '').trim().toUpperCase())
        .filter((l) => l in SEVERITY_RANK)
        .sort((a, b) => (SEVERITY_RANK[b] ?? 0) - (SEVERITY_RANK[a] ?? 0));
      const priority = rankPriority({
        exploitedWild: flags.exploited_wild,
        ransomware: flags.ransomware,
        malicious: flags.malicious,
        publicExploit: flags.public_exploit,
        poc: flags.poc,
        epss: vuln?.epss ?? null,
        cvss: rankCvss,
        severityLabel: labels[0] ?? null,
      });

      // Fix versions: reviewed records with full display only.
      const fixRows = g.covering.filter((row) => mode(row.source) === 'full');
      const fix: FixChoice | null = fixedInFor(ref.ecosystem, ref.version, fixRows, rules);

      const recSorted = [...g.records].sort((a, b) => cmp(a.source_id, b.source_id));
      const summaryRec = [...full].sort(
        (a, b) =>
          Number((b.rows[0] as AffectedRecordRow).reviewed) -
            Number((a.rows[0] as AffectedRecordRow).reviewed) || cmp(a.source_id, b.source_id),
      )[0];
      const httpsUrl = recSorted
        .map((r) => (r.rows[0] as AffectedRecordRow).url)
        .find((u): u is string => typeof u === 'string' && u.startsWith('https://'));
      const url = vuln
        ? `${origin}/e/${encodeURIComponent(key)}`
        : (httpsUrl ?? `${origin}/search?q=${encodeURIComponent(key)}`);
      const sources = [...new Set([...g.records.map((r) => r.source), ...sig.map((s) => s.source)])].sort(
        cmp,
      );
      for (const s of sources) usedSources.add(s);
      if (vuln && cvssVisible !== null) for (const id of cvssCandidates(vuln)) usedSources.add(id);

      const match: CheckMatch = {
        id: key,
        title: vuln?.title ?? null,
        summary: summaryRec ? ((summaryRec.rows[0] as AffectedRecordRow).summary ?? null) : null,
        fixedIn: fix?.value ?? null,
        signals,
        cvss: cvssVisible,
        epss: vuln?.epss ?? null,
        url,
        sources,
      };
      return { match, priority, fix, malicious: flags.malicious };
    });

    if (built.length > 0) {
      built.sort(
        (a, b) => priorityRank(a.priority) - priorityRank(b.priority) || cmp(a.match.id, b.match.id),
      );
      const top = built[0]?.priority as Priority;
      const up = pickUpgrade(
        ref.ecosystem,
        ref.version,
        built.map((b) => ({ id: b.match.id, malicious: b.malicious, fix: b.fix })),
        allRows,
        rules,
      );
      results.push({
        package: ref,
        priority: top,
        upgradeTo: up.upgradeTo,
        upgradeNote: up.upgradeNote,
        matches: built.slice(0, MAX_MATCHES_PER_PACKAGE).map((b) => b.match),
        omitted: Math.max(0, built.length - MAX_MATCHES_PER_PACKAGE),
      });
    }
    if (uncertainKeys.size > 0) {
      for (const rec of records) if (uncertainKeys.has(rec.vuln_key)) usedSources.add(rec.source);
      uncertain.push({ package: ref, ids: [...uncertainKeys].sort(cmp), reason: 'version_rules_pending' });
    }
    if (built.length === 0 && uncertainKeys.size === 0) noRecord.push(ref);
  }

  results.sort(
    (a, b) =>
      priorityRank(a.priority) - priorityRank(b.priority) ||
      cmp(a.package.ecosystem, b.package.ecosystem) ||
      cmp(a.package.name, b.package.name) ||
      cmp(a.package.version, b.package.version),
  );
  const summary: Record<Priority, number> = { fix_now: 0, fix_soon: 0, plan: 0, note: 0 };
  for (const r of results) summary[r.priority]++;

  const notes: string[] = [NOTES.noRecord, NOTES.reachability, NOTES.fixes];
  if (uncertain.length > 0) notes.push(NOTES.uncertain);
  if (entries.some((e) => e.private)) notes.push(NOTES.private);
  if (input.needsRelease) notes.push(NOTES.release);
  notes.push(NOTES.sources);

  return {
    response: {
      asOf: input.now.toISOString(),
      checked: entries.length,
      matched: results.length,
      summary,
      results,
      noRecord,
      uncertain,
      confusion,
      rejected: [...rejected],
      notes,
      credits: creditsFor([...usedSources].sort(cmp), data.display),
    },
    stats: {
      matched: results.length,
      uncertain: uncertain.length,
      confusion: confusion.length,
      unknownNames,
      ecosystems: ecosystems.size,
    },
  };
}

/** The answer for a request where nothing was accepted: `rejected` and `notes` only, no reads. */
export function emptyAnswer(
  rejected: readonly RejectedEntry[],
  now: Date,
  needsRelease = false,
): CheckResponse {
  const notes: string[] = [NOTES.noRecord, NOTES.reachability, NOTES.fixes];
  if (needsRelease) notes.push(NOTES.release);
  notes.push(NOTES.sources);
  return {
    asOf: now.toISOString(),
    checked: 0,
    matched: 0,
    summary: { fix_now: 0, fix_soon: 0, plan: 0, note: 0 },
    results: [],
    noRecord: [],
    uncertain: [],
    confusion: [],
    rejected: [...rejected],
    notes,
    credits: [],
  };
}
