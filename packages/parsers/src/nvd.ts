import { normaliseId } from '@ti/core/ids';
import type { AdvisoryRecord, ParsedRecord, ParseResult, VulnRecord } from '@ti/core/types';
import { z } from 'zod';
import {
  asArray,
  asRecord,
  bestScore,
  CWE_ID,
  clip,
  englishText,
  firstSentence,
  type Score,
  SUMMARY_MAX,
  TITLE_MAX,
  toIso,
} from './cve-json5';

/** NVD CVE API 2.0: a response with `vulnerabilities[]`, or one `{ cve }`. */

const Cve = z.looseObject({ id: z.string(), lastModified: z.string() });
const Wrapper = z.looseObject({ cve: Cve });
const Response = z.looseObject({ vulnerabilities: z.array(Wrapper) });

const KNOWN_CVE = new Set([
  'id',
  'sourceIdentifier',
  'vulnStatus',
  'published',
  'lastModified',
  'descriptions',
  'metrics',
  'weaknesses',
  // Known, not mapped in this change.
  'configurations',
  'references',
  'affected',
  'cveTags',
  'vendorComments',
  'evaluatorComment',
  'evaluatorImpact',
  'evaluatorSolution',
  'cisaExploitAdd',
  'cisaActionDue',
  'cisaRequiredAction',
  'cisaVulnerabilityName',
]);

const METRIC_KEYS = {
  cvssMetricV31: '3.1',
  cvssMetricV40: '4.0',
  cvssMetricV30: '3.0',
  cvssMetricV2: '2.0',
} as const;

/** Only NVD's own analysis (`type: 'Primary'`); the CNA's copy arrives through `cve-list`. */
function primaryScore(metrics: unknown): Score | undefined {
  const found: Partial<Record<Score['cvssVersion'], number>> = {};
  const m = asRecord(metrics);
  for (const [key, version] of Object.entries(METRIC_KEYS))
    for (const entry of asArray(m[key])) {
      const r = asRecord(entry);
      const score = asRecord(r.cvssData).baseScore;
      if (r.type === 'Primary' && typeof score === 'number' && found[version] === undefined)
        found[version] = score;
    }
  return bestScore(found);
}

function cwes(weaknesses: unknown): string[] {
  const out = new Set<string>();
  for (const w of asArray(weaknesses))
    for (const d of asArray(asRecord(w).description)) {
      const v = asRecord(d).value;
      if (typeof v === 'string' && CWE_ID.test(v)) out.add(v);
    }
  return [...out];
}

function parseInput(input: unknown): z.infer<typeof Cve>[] {
  let doc = input;
  if (typeof doc === 'string') {
    try {
      doc = JSON.parse(doc);
    } catch {
      throw new Error('nvd: not valid JSON');
    }
  }
  const resp = Response.safeParse(doc);
  if (resp.success) return resp.data.vulnerabilities.map((v) => v.cve);
  const one = Wrapper.safeParse(doc);
  if (one.success) return [one.data.cve];
  const issue = resp.error.issues[0];
  throw new Error(
    `nvd: expected a CVE API 2.0 response or { cve } (${issue?.path.join('.') || 'document'}: ${issue?.message})`,
  );
}

export function parseNvd(input: unknown): ParseResult<ParsedRecord> {
  const records: ParsedRecord[] = [];
  const unknown = new Set<string>();

  for (const cve of parseInput(input)) {
    for (const k of Object.keys(cve)) if (!KNOWN_CVE.has(k)) unknown.add(`cve.${k}`);
    const id = normaliseId(cve.id);
    const modified = toIso(cve.lastModified);
    if (modified === undefined) throw new Error(`nvd: ${id} has an unusable lastModified`);
    const published = toIso(cve.published);

    if (cve.vulnStatus === 'Rejected') {
      records.push({
        source: 'nvd',
        sourceId: id,
        vulnKey: id,
        status: 'rejected',
        ...(published ? { published } : {}),
        modified,
      } satisfies AdvisoryRecord);
      continue;
    }

    const summary = clip(englishText(cve.descriptions), SUMMARY_MAX);
    const name =
      typeof cve.cisaVulnerabilityName === 'string' ? clip(cve.cisaVulnerabilityName, TITLE_MAX) : '';
    const score = primaryScore(cve.metrics);
    records.push({
      key: id,
      kind: 'cve',
      title: name || clip(firstSentence(summary, 120), TITLE_MAX) || id,
      summary,
      ...(published ? { published } : {}),
      modified,
      ...(score ?? {}),
      ...(score ? { cvssSource: 'nvd' } : {}),
      cwe: cwes(cve.weaknesses),
      aliases: [],
      source: 'nvd',
    } satisfies VulnRecord);
  }

  return { records, unknownFields: [...unknown] };
}

/** The parser-module contract: `@ti/parsers/nvd` exports `parse`. */
export const parse = parseNvd;
