import type { ParseResult, TechniqueRecord } from '@ti/core/types';
import { clip, SUMMARY_MAX } from './cve-json5';

/**
 * One STIX 2.1 parser for both MITRE catalogues: ATT&CK (enterprise) and ATLAS. Reads only
 * `attack-pattern` objects (plus the collection's version); relationships are not read, a
 * sub-technique's parent comes from its id. No Node-only imports.
 */

export const MAX_TECHNIQUES = 5000;
const NAME_MAX = 200;

const KNOWN_TYPES = new Set([
  'relationship',
  'x-mitre-analytic',
  'attack-pattern',
  'malware',
  'x-mitre-detection-strategy',
  'course-of-action',
  'intrusion-set',
  'x-mitre-data-component',
  'tool',
  'campaign',
  'x-mitre-data-source',
  'x-mitre-tactic',
  'x-mitre-collection',
  'x-mitre-matrix',
  'identity',
  'marking-definition',
]);

const SOURCES = [
  { name: 'mitre-attack', framework: 'attack', id: /^T\d{4}(\.\d{3})?$/ },
  { name: 'mitre-atlas', framework: 'atlas', id: /^AML\.T\d{4}(\.\d{3})?$/ },
] as const;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

function identify(o: Obj): { id: string; framework: 'attack' | 'atlas' } | null {
  if (!Array.isArray(o.external_references)) return null;
  for (const ref of o.external_references) {
    if (!isObj(ref) || typeof ref.external_id !== 'string') continue;
    for (const s of SOURCES)
      if (ref.source_name === s.name && s.id.test(ref.external_id))
        return { id: ref.external_id, framework: s.framework };
  }
  return null;
}

/** Descriptions are Markdown with citation markers and links; keep plain text only. */
function plainSummary(description: unknown): string {
  if (typeof description !== 'string') return '';
  const text = description
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]*>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return clip(text, SUMMARY_MAX);
}

export function parseStix(input: unknown): ParseResult<TechniqueRecord> & { version?: string } {
  let bundle = input;
  if (typeof bundle === 'string') {
    try {
      bundle = JSON.parse(bundle);
    } catch (cause) {
      throw new Error('stix: invalid JSON', { cause });
    }
  }
  if (!isObj(bundle) || bundle.type !== 'bundle' || !Array.isArray(bundle.objects))
    throw new Error('stix: expected a STIX bundle');

  const unknown = new Set<string>();
  let version: string | undefined;
  // id -> chosen object; Map keeps first-insertion order, a replaced value keeps its place.
  const chosen = new Map<string, { record: TechniqueRecord; modified: string }>();

  for (const o of bundle.objects) {
    if (!isObj(o) || typeof o.type !== 'string') continue;
    if (!KNOWN_TYPES.has(o.type)) unknown.add(`type:${o.type}`);
    if (o.type === 'x-mitre-collection' && version === undefined && typeof o.x_mitre_version === 'string')
      version = o.x_mitre_version;
    if (o.type !== 'attack-pattern') continue;
    if (o.revoked === true || o.x_mitre_deprecated === true) continue;
    if (typeof o.name !== 'string') continue;
    const name = clip(o.name.replace(/\s+/g, ' ').trim(), NAME_MAX);
    if (!name) continue;
    const ident = identify(o);
    if (!ident) continue;

    const summary = plainSummary(o.description);
    const record: TechniqueRecord = {
      id: ident.id,
      framework: ident.framework,
      name,
      ...(summary ? { summary } : {}),
    };
    const modified = typeof o.modified === 'string' ? o.modified : '';
    const prior = chosen.get(ident.id);
    if (prior && modified < prior.modified) continue;
    chosen.set(ident.id, { record, modified });
    if (chosen.size > MAX_TECHNIQUES) throw new Error('stix: too many techniques');
  }

  const records: TechniqueRecord[] = [];
  for (const { record } of chosen.values()) {
    const dot = record.id.lastIndexOf('.');
    const parentId = /\.\d{3}$/.test(record.id) ? record.id.slice(0, dot) : undefined;
    records.push(parentId && chosen.has(parentId) ? { ...record, parent: parentId } : record);
  }

  return { records, unknownFields: [...unknown].sort(), ...(version !== undefined ? { version } : {}) };
}

/** The parser-module contract: `@ti/parsers/stix` exports `parse`. */
export const parse = parseStix;
