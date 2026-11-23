import type { AdvisoryRecord, ParseResult } from '@ti/core/types';
import { cveList, isoMs, perCve } from './cert-common';

/**
 * CERT/CC vulnerability notes. Two inputs give the same records: one `<entry>` of the Atom feed
 * (`https://kb.cert.org/vuls/atomfeed/`, as `fast-xml-parser` reads it) or one note from the note API
 * (`https://kb.cert.org/vuls/api/<n>/`). IDs, dates, URL and CVEs only; titles and prose are never copied.
 * The base id is `VU-<n>`: the `#` of `VU#<n>` fails the linker's id rule.
 */

type Node = Record<string, unknown>;

const NOTE_URL = /^https:\/\/kb\.cert\.org\/vuls\/id\/(\d{1,7})\/?$/;
const ENTRY_KEYS = new Set([
  'title',
  'link',
  'published',
  'updated',
  'id',
  'summary',
  'content',
  'author',
  'category',
]);

/** The key set of `fixtures/cert-cc/note-604762.json`. A key outside it is reported, never a crash. */
export const CERT_CC_NOTE_KEYS: readonly string[] = [
  'vuid',
  'idnumber',
  'name',
  'keywords',
  'overview',
  'clean_desc',
  'impact',
  'resolution',
  'workarounds',
  'sysaffected',
  'thanks',
  'author',
  'public',
  'cveids',
  'certadvisory',
  'uscerttechnicalalert',
  'datecreated',
  'publicdate',
  'datefirstpublished',
  'dateupdated',
  'revision',
  'vrda_d1_directreport',
  'vrda_d1_population',
  'vrda_d1_impact',
  'cam_widelyknown',
  'cam_exploitation',
  'cam_internetinfrastructure',
  'cam_population',
  'cam_impact',
  'cam_easeofexploitation',
  'cam_attackeraccessrequired',
  'cam_scorecurrent',
  'cam_scorecurrentwidelyknown',
  'cam_scorecurrentwidelyknownexploited',
  'ipprotocol',
  'cvss_accessvector',
  'cvss_accesscomplexity',
  'cvss_authentication',
  'cvss_confidentialityimpact',
  'cvss_integrityimpact',
  'cvss_availabilityimpact',
  'cvss_exploitablity',
  'cvss_remediationlevel',
  'cvss_reportconfidence',
  'cvss_collateraldamagepotential',
  'cvss_targetdistribution',
  'cvss_securityrequirementscr',
  'cvss_securityrequirementsir',
  'cvss_securityrequirementsar',
  'cvss_basescore',
  'cvss_basevector',
  'cvss_temporalscore',
  'cvss_environmentalscore',
  'cvss_environmentalvector',
  'metric',
  'vulnote',
];
const NOTE_KEYS = new Set(CERT_CC_NOTE_KEYS);

/** The CVE IDs block links each CVE to NVD. Only those links count: the prose also names related CVEs. */
const NVD_LINK =
  /href\s*=\s*["']https?:\/\/web\.nvd\.nist\.gov\/view\/vuln\/detail\?(?:[^"'#]*&(?:amp;)?)?vulnId=(\d{4}-\d{4,})["'&]/gi;

function textOf(v: unknown): string {
  if (typeof v === 'string') return v.trim();
  if (typeof v === 'number') return String(v);
  if (Array.isArray(v)) return textOf(v[0]);
  if (v && typeof v === 'object' && '#text' in v) return textOf((v as Node)['#text']);
  return '';
}

function asObject(input: unknown): Node {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      throw new Error('cert-cc: input is not valid JSON');
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('cert-cc: expected an object');
  }
  return value as Node;
}

function noteUrl(number: string): string {
  return `https://kb.cert.org/vuls/id/${number}`;
}

function build(
  number: string,
  cves: string[],
  published: string | null,
  modified: string | null,
  unknownFields: string[],
): ParseResult<AdvisoryRecord> {
  const mod = modified ?? published;
  if (mod === null) throw new Error('cert-cc: note has no valid modified date');
  const records = perCve(`VU-${number}`, cveList(cves), {
    source: 'cert-cc',
    status: 'active',
    ...(published ? { published } : {}),
    modified: mod,
    url: noteUrl(number),
  });
  return { records, unknownFields };
}

export function parseCertCcEntry(input: unknown): ParseResult<AdvisoryRecord> {
  const entry = asObject(input);
  const unknownFields = Object.keys(entry).filter((k) => !ENTRY_KEYS.has(k));

  const links = Array.isArray(entry.link) ? entry.link : [entry.link];
  const href = links
    .map((l) => (l && typeof l === 'object' ? textOf((l as Node)['@_href']) : ''))
    .find((h) => h !== '');
  const ref = textOf(entry.id) || href || '';
  const m = NOTE_URL.exec(ref);
  if (!m) throw new Error('cert-cc: entry id is not a kb.cert.org note URL');

  const cves: string[] = [];
  for (const hit of textOf(entry.content).matchAll(NVD_LINK)) cves.push(`CVE-${hit[1]}`);

  const published = isoMs(textOf(entry.published));
  return build(m[1] as string, cves, published, isoMs(textOf(entry.updated)), unknownFields);
}

export function parseCertCcNote(input: unknown): ParseResult<AdvisoryRecord> {
  const note = asObject(input);
  const unknownFields = Object.keys(note).filter((k) => !NOTE_KEYS.has(k));

  const number = textOf(note.idnumber);
  if (!/^\d{1,7}$/.test(number)) throw new Error('cert-cc: note has no valid idnumber');

  const published = isoMs(note.datefirstpublished) ?? isoMs(note.publicdate);
  const cves = Array.isArray(note.cveids) ? (note.cveids as unknown[]) : [];
  return build(number, cves as string[], published, isoMs(note.dateupdated), unknownFields);
}

/** The parser-module contract: a note (an object with `vuid` or `idnumber`, or its JSON) or a feed entry. */
export function parse(input: unknown): ParseResult<AdvisoryRecord> {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      value = input;
    }
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && ('vuid' in value || 'idnumber' in value))
    return parseCertCcNote(value);
  return parseCertCcEntry(input);
}
