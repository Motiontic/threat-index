import { isCve, normaliseId } from '@ti/core/ids';
import type { AdvisoryRecord, Affected, ParseResult, SignalRecord } from '@ti/core/types';
import { z } from 'zod';
import { asArray, asRecord, clip, toIso } from './cve-json5';

/**
 * CSAF 2.0 (Red Hat VEX, Microsoft MSRC, Cisco, Oracle CPU): one parser for every vendor source. It reads
 * metadata only: which CVE, which products, whether a fix shipped, whether the vendor says it is exploited.
 * No notes, descriptions, remediation text or scores are copied.
 */

/** Publisher namespace host -> source id. */
export const CSAF_PUBLISHERS: Readonly<Record<string, string>> = {
  'www.redhat.com': 'red-hat',
  'redhat.com': 'red-hat',
  'msrc.microsoft.com': 'msrc',
  'www.microsoft.com': 'msrc',
  'cisco.com': 'cisco',
  'www.cisco.com': 'cisco',
  'www.oracle.com': 'oracle',
  'oracle.com': 'oracle',
};

export const AFFECTED_MAX = 20;
const NAME_MAX = 200;
const ID_OK = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const isUrl = (s: string) => {
  try {
    new URL(s);
    return true;
  } catch {
    return false;
  }
};

const Csaf = z.looseObject({
  document: z.looseObject({
    csaf_version: z.string().regex(/^2\./),
    tracking: z.looseObject({
      id: z.string(),
      status: z.unknown().optional(),
      initial_release_date: z.unknown().optional(),
      current_release_date: z.string().refine((s) => toIso(s) !== undefined, 'not a date'),
    }),
    publisher: z.looseObject({
      name: z.unknown().optional(),
      namespace: z.string().refine(isUrl, 'not a URL'),
    }),
    references: z.unknown().optional(),
  }),
  product_tree: z.unknown().optional(),
  vulnerabilities: z.unknown().optional(),
});

const KNOWN = {
  csaf: ['document', 'product_tree', 'vulnerabilities'],
  document: [
    'acknowledgments',
    'aggregate_severity',
    'category',
    'csaf_version',
    'distribution',
    'lang',
    'notes',
    'publisher',
    'references',
    'source_lang',
    'title',
    'tracking',
  ],
  vulnerabilities: [
    'acknowledgments',
    'cve',
    'cwe',
    'discovery_date',
    'flags',
    'ids',
    'involvements',
    'notes',
    'product_status',
    'references',
    'release_date',
    'remediations',
    'scores',
    'threats',
    'title',
  ],
} as const;

// Order matters: it is the order of the `affected` list.
const STATUS_KEYS = [
  'fixed',
  'first_fixed',
  'recommended',
  'known_affected',
  'first_affected',
  'last_affected',
  'under_investigation',
  'known_not_affected',
] as const;
const FIXED_KEYS = new Set<string>(['fixed', 'first_fixed', 'recommended']);
const RANGE_OF: Record<string, string> = {
  known_affected: 'affected',
  first_affected: 'affected',
  last_affected: 'affected',
  under_investigation: 'under investigation',
  known_not_affected: 'not affected',
};
const VERSION_CATEGORIES = new Set(['product_version', 'service_pack', 'patch_level']);

function reportUnknown(
  into: Set<string>,
  prefix: string,
  obj: Record<string, unknown>,
  known: readonly string[],
) {
  for (const k of Object.keys(obj)) if (!known.includes(k)) into.add(`${prefix}.${k}`);
}

/** Looks like the `changelist` pattern's `ChangeItem` (that package is not a dependency of this one). */
function isChangeItem(x: unknown): x is { ref: string; time: string; text: string | null } {
  const r = asRecord(x);
  return typeof r.ref === 'string' && typeof r.time === 'string' && 'text' in r && !('document' in r);
}

function load(input: unknown): unknown {
  let doc = input;
  if (isChangeItem(doc)) {
    if (doc.text === null) return undefined;
    doc = doc.text;
  }
  if (typeof doc === 'string') {
    try {
      doc = JSON.parse(doc);
    } catch {
      throw new Error('csaf: not valid JSON');
    }
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc) || !('document' in doc))
    throw new Error('csaf: expected a CSAF document, its JSON text or a change item');
  return doc;
}

interface Product {
  name: string;
  version?: string;
  vendor: string;
}

function productMap(tree: Record<string, unknown>, publisherName: string): Map<string, Product> {
  const map = new Map<string, Product>();
  const walk = (branches: unknown, version: string | undefined, vendor: string) => {
    for (const raw of asArray(branches)) {
      const b = asRecord(raw);
      const name = typeof b.name === 'string' ? b.name : undefined;
      const ver = typeof b.category === 'string' && VERSION_CATEGORIES.has(b.category) ? name : version;
      const ven = b.category === 'vendor' && name ? name : vendor;
      const p = asRecord(b.product);
      if (typeof p.product_id === 'string' && typeof p.name === 'string')
        map.set(p.product_id, { name: p.name, ...(ver ? { version: ver } : {}), vendor: ven });
      walk(b.branches, ver, ven);
    }
  };
  walk(tree.branches, undefined, publisherName);
  const addNamed = (fpn: unknown, ref: unknown) => {
    const f = asRecord(fpn);
    if (typeof f.product_id !== 'string' || typeof f.name !== 'string') return;
    const base = typeof ref === 'string' ? map.get(ref) : undefined;
    map.set(f.product_id, {
      name: f.name,
      ...(base?.version ? { version: base.version } : {}),
      vendor: base?.vendor ?? publisherName,
    });
  };
  for (const f of asArray(tree.full_product_names)) addNamed(f, undefined);
  for (const r of asArray(tree.relationships)) {
    const rel = asRecord(r);
    addNamed(rel.full_product_name, rel.product_reference);
  }
  return map;
}

function affectedOf(status: Record<string, unknown>, products: Map<string, Product>): Affected[] {
  const out: Affected[] = [];
  const seen = new Set<string>();
  for (const key of STATUS_KEYS) {
    for (const id of asArray(status[key])) {
      if (out.length >= AFFECTED_MAX) return out;
      const p = typeof id === 'string' ? products.get(id) : undefined;
      if (!p) continue;
      const range = RANGE_OF[key];
      const name = clip(p.name, NAME_MAX);
      const dedupe = `${name}\u0000${range ?? ''}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      out.push(
        FIXED_KEYS.has(key)
          ? { ecosystem: p.vendor, name, fixed: clip(p.version ?? p.name, NAME_MAX) }
          : { ecosystem: p.vendor, name, ...(range ? { range } : {}) },
      );
    }
  }
  return out;
}

const httpUrl = (s: unknown): string | undefined => {
  if (typeof s !== 'string') return undefined;
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:' ? s : undefined;
  } catch {
    return undefined;
  }
};

const pathOf = (url: string) => new URL(url).pathname;

function selfUrl(refs: unknown): string | undefined {
  for (const r of asArray(refs)) {
    const ref = asRecord(r);
    const u = ref.category === 'self' ? httpUrl(ref.url) : undefined;
    if (u && !pathOf(u).endsWith('.json')) return u;
  }
  return undefined;
}

function htmlUrl(refs: unknown): string | undefined {
  for (const r of asArray(refs)) {
    const u = httpUrl(asRecord(r).url);
    if (u && pathOf(u).endsWith('.html')) return u;
  }
  return undefined;
}

const day = (iso: string | undefined) => iso?.slice(0, 10);

export function parseCsaf(
  input: unknown,
  opts: { source?: string } = {},
): ParseResult<AdvisoryRecord | SignalRecord> {
  const raw = load(input);
  if (raw === undefined) return { records: [], unknownFields: [] };
  const parsed = Csaf.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.join('.') ?? '';
    throw new Error(`csaf: ${path ? `${path}: ` : ''}${issue?.message ?? 'invalid document'}`);
  }
  const csaf = parsed.data as Record<string, unknown>;
  const doc = asRecord(csaf.document);
  const tracking = asRecord(doc.tracking);
  const publisher = asRecord(doc.publisher);

  const host = new URL(publisher.namespace as string).hostname;
  const source = opts.source ?? CSAF_PUBLISHERS[host];
  if (!source) throw new Error(`csaf: unknown publisher ${host}`);

  const unknown = new Set<string>();
  reportUnknown(unknown, 'csaf', csaf, KNOWN.csaf);
  reportUnknown(unknown, 'document', doc, KNOWN.document);

  const none = { records: [], unknownFields: [...unknown] };
  if (tracking.status === 'draft') return none;
  const vulns = csaf.vulnerabilities;
  if (!Array.isArray(vulns)) return none;

  const modified = toIso(tracking.current_release_date) as string;
  const initial = toIso(tracking.initial_release_date);
  const trackingId = tracking.id as string;
  const products = productMap(
    asRecord(csaf.product_tree),
    typeof publisher.name === 'string' ? publisher.name : source,
  );
  const records: Array<AdvisoryRecord | SignalRecord> = [];

  for (const rawVuln of vulns) {
    const v = asRecord(rawVuln);
    reportUnknown(unknown, 'vulnerabilities', v, KNOWN.vulnerabilities);
    const status = asRecord(v.product_status);
    for (const k of Object.keys(status))
      if (!(STATUS_KEYS as readonly string[]).includes(k)) unknown.add(`product_status.${k}`);
    if (typeof v.cve !== 'string' || !isCve(v.cve)) continue;
    const cve = normaliseId(v.cve);
    const docId = normaliseId(trackingId);
    const sourceId = docId === cve ? cve : `${docId}:${cve}`;
    if (!ID_OK.test(cve) || !ID_OK.test(sourceId)) continue;

    const url = selfUrl(v.references) ?? selfUrl(doc.references) ?? htmlUrl(doc.references);
    const affected = affectedOf(status, products);
    const published = toIso(v.release_date) ?? initial;
    records.push({
      source,
      sourceId,
      vulnKey: cve,
      status: 'active',
      ...(published ? { published } : {}),
      modified,
      ...(url ? { url } : {}),
      ...(affected.length ? { affected } : {}),
    });

    const exploited = asArray(v.threats).some((t) => {
      const th = asRecord(t);
      return (
        th.category === 'exploit_status' &&
        typeof th.details === 'string' &&
        /\bExploited:\s*Yes\b/i.test(th.details)
      );
    });
    if (exploited)
      records.push({
        vulnKey: cve,
        kind: 'exploited_wild',
        source,
        ref: trackingId,
        firstSeen: (day(initial) ?? day(modified)) as string,
        evidenceDate: day(modified) as string,
        ...(url ? { url } : {}),
      });
  }
  return { records, unknownFields: [...unknown] };
}

export const parse = (input: unknown) => parseCsaf(input);
