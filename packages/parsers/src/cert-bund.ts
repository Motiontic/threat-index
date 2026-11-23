import type { AdvisoryRecord, ParseResult } from '@ti/core/types';
import { cveList, isoMs, perCve } from './cert-common';

/**
 * BSI CERT-Bund CSAF 2.0 advisories (`https://wid.cert-bund.de/.well-known/csaf/white/`). A minimal reader for BSI
 * only: the shared CSAF parser (`csaf.ts`) is a separate piece of work and may absorb this later. IDs, CVEs, dates
 * and the portal link only; `notes`, `product_tree` and every title are never read.
 * No Node-only imports: runs in Workers and E2B.
 */

type Node = Record<string, unknown>;

const TRACKING_ID = /^WID-SEC-W-\d{4}-\d{1,6}$/;
const TOP_KEYS = new Set(['document', 'product_tree', 'vulnerabilities']);
const DOCUMENT_KEYS = new Set([
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
]);
const PORTAL = 'https://wid.cert-bund.de/portal/';

const isObject = (v: unknown): v is Node => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A ChangeItem from the changelist pattern: `{ ref, time, text }`. The document is in `text`. */
function isChangeItem(v: Node): boolean {
  return 'text' in v && 'ref' in v && !('document' in v);
}

export function parseCertBund(input: unknown): ParseResult<AdvisoryRecord> {
  let value = input;
  if (isObject(value) && isChangeItem(value)) {
    if (value.text === null) return { records: [], unknownFields: [] };
    value = value.text;
  }
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('bsi-cert-bund: input is not valid JSON');
    }
  }
  if (!isObject(value)) throw new Error('bsi-cert-bund: expected a CSAF document object');
  const doc = value.document;
  if (!isObject(doc)) throw new Error('bsi-cert-bund: document is missing');
  const tracking = isObject(doc.tracking) ? doc.tracking : {};

  const id = typeof tracking.id === 'string' ? tracking.id : '';
  if (!TRACKING_ID.test(id)) throw new Error('bsi-cert-bund: document.tracking.id is not a WID-SEC-W id');
  const modified = isoMs(tracking.current_release_date);
  if (modified === null) throw new Error('bsi-cert-bund: no valid current_release_date');

  const distribution = isObject(doc.distribution) ? doc.distribution : {};
  const tlp = isObject(distribution.tlp) ? distribution.tlp : {};
  if (tlp.label !== undefined) {
    const label = typeof tlp.label === 'string' ? tlp.label.toUpperCase() : '';
    if (label !== 'WHITE' && label !== 'CLEAR') return { records: [], unknownFields: ['tlp'] };
  }
  if (tracking.status === 'draft') return { records: [], unknownFields: [] };

  const unknownFields = [
    ...Object.keys(value).filter((k) => !TOP_KEYS.has(k)),
    ...Object.keys(doc)
      .filter((k) => !DOCUMENT_KEYS.has(k))
      .map((k) => `document.${k}`),
  ];

  const vulns = Array.isArray(value.vulnerabilities) ? value.vulnerabilities : [];
  const cves = cveList(vulns.map((v) => (isObject(v) ? v.cve : undefined)));

  const refs = Array.isArray(doc.references) ? doc.references : [];
  const portal = refs
    .map((r) => (isObject(r) && typeof r.url === 'string' ? r.url : ''))
    .find((u) => u.startsWith(PORTAL));
  const published = isoMs(tracking.initial_release_date);

  const records = perCve(id, cves, {
    source: 'bsi-cert-bund',
    status: doc.category === 'csaf_withdrawn' ? 'withdrawn' : 'active',
    ...(published ? { published } : {}),
    modified,
    ...(portal ? { url: portal } : {}),
  });
  return { records, unknownFields };
}

/** The parser-module contract: `@ti/parsers/cert-bund` exports `parse`. */
export const parse = parseCertBund;
