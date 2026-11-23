import type { ParseResult, SignalKind, SignalRecord } from '@ti/core/types';
import { z } from 'zod';
import { cveRefs, isoDay, SAFE_REF } from './exploit-db';

/**
 * Metasploit `db/modules_metadata_base.json` parser. Metadata only: the module name, its CVEs and
 * dates. Descriptions, authors and file paths are never copied. Worker-safe.
 */

export const MAX_MODULES = 50_000;

const Module = z.looseObject({
  fullname: z.string(),
  type: z.string(),
  references: z.array(z.string()),
  disclosure_date: z.string().nullable().optional(),
  mod_time: z.string(),
});

const KNOWN_KEYS = new Set([
  'name',
  'fullname',
  'aliases',
  'rank',
  'disclosure_date',
  'type',
  'author',
  'description',
  'references',
  'platform',
  'arch',
  'rport',
  'autofilter_ports',
  'autofilter_services',
  'targets',
  'mod_time',
  'path',
  'is_install_path',
  'ref_name',
  'check',
  'post_auth',
  'default_credential',
  'notes',
  'session_types',
  'needs_cleanup',
  'actions',
  'adapter_refname',
  'adapter',
  'stage_refname',
  'stage',
  'staged',
  'payload_type',
]);

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

function kindOf(type: string, fullname: string): SignalKind | null {
  if (type === 'exploit') return 'public_exploit';
  if (type === 'auxiliary') return fullname.startsWith('auxiliary/scanner/') ? 'detection' : 'public_exploit';
  return null;
}

/** A `GitFile` (has `path` and `text`), JSON text, the whole object, or one module -> module list. */
function modulesOf(input: unknown): unknown[] {
  let value = input;
  if (isObj(value) && !('fullname' in value) && 'text' in value && 'path' in value) {
    if (value.status === 'removed' || value.text === null || value.text === undefined) return [];
    value = value.text;
  }
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (err) {
      throw new Error('metasploit: invalid JSON', { cause: err });
    }
  }
  if (!isObj(value)) throw new Error('metasploit: input is not an object');
  if ('fullname' in value) return [value];
  const mods = Object.values(value);
  if (mods.length > MAX_MODULES) throw new Error(`metasploit: more than ${MAX_MODULES} modules`);
  return mods;
}

export function parseMetasploit(input: unknown): ParseResult<SignalRecord> & { skipped: number } {
  const mods = modulesOf(input);
  const unknown = new Set<string>();
  const records: SignalRecord[] = [];
  let skipped = 0;
  for (const raw of mods) {
    const parsed = Module.safeParse(raw);
    if (!parsed.success) {
      skipped++;
      continue;
    }
    const m = parsed.data;
    for (const k of Object.keys(m)) if (!KNOWN_KEYS.has(k)) unknown.add(k);
    const kind = kindOf(m.type, m.fullname);
    if (!kind) continue;
    const cves = cveRefs(m.references);
    if (cves.length === 0) continue;
    const firstSeen = isoDay(m.mod_time);
    if (!firstSeen || !SAFE_REF.test(m.fullname)) {
      skipped++;
      continue;
    }
    const evidenceDate = isoDay(m.disclosure_date);
    for (const vulnKey of cves) {
      records.push({
        vulnKey,
        kind,
        source: 'metasploit',
        ref: m.fullname,
        firstSeen,
        ...(evidenceDate ? { evidenceDate } : {}),
        url: `https://github.com/rapid7/metasploit-framework/blob/master/modules/${m.fullname}.rb`,
      });
    }
  }
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = parseMetasploit;
