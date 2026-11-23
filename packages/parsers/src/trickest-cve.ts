import { normaliseId } from '@ti/core/ids';
import type { ParseResult, SignalRecord } from '@ti/core/types';
import { SAFE_REF } from './exploit-db';
import { MAX_POC_PER_CVE } from './poc-in-github';

/**
 * trickest/cve parser. One Markdown file per CVE (`<yyyy>/CVE-<id>.md`). Only the links under its
 * `#### Github` heading are read, as weak proof-of-concept signals. Descriptions are never copied
 * and no code is fetched. Worker-safe.
 */

const PATH = /(?:^|\/)(CVE-\d{4}-\d{4,})\.md$/;
const FULL_NAME = /^[\w.-]+\/[\w.-]+$/;
const LINK = /^- https:\/\/github\.com\/([^/\s]+\/[^/\s]+)\/?$/;
const HEADING = /^(#{1,6})\s+(.*?)\s*$/;
const KNOWN_HEADINGS = new Set(['description', 'poc', 'reference', 'github']);

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

export function parseTrickestCve(
  input: unknown,
  today: Date,
): ParseResult<SignalRecord> & { skipped: number } {
  const empty = { records: [], unknownFields: [], skipped: 0 };
  if (!isObj(input) || typeof input.path !== 'string' || !('text' in input))
    throw new Error('trickest-cve: input must be a GitFile');
  if (input.status === 'removed' || input.text === null || input.text === undefined) return empty;
  const m = PATH.exec(input.path);
  if (!m) return empty;
  if (typeof input.text !== 'string') throw new Error('trickest-cve: GitFile text must be a string');
  const vulnKey = normaliseId(m[1] as string);
  const firstSeen = today.toISOString().slice(0, 10);

  const unknown = new Set<string>();
  const seen = new Set<string>();
  const refs: string[] = [];
  let skipped = 0;
  let inGithub = false;
  for (const raw of input.text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const h = HEADING.exec(line);
    if (h) {
      const text = h[2] as string;
      inGithub = h[1] === '####' && text.toLowerCase() === 'github';
      // The title heading is `### [CVE-...](link)`; it is part of every file.
      const known = KNOWN_HEADINGS.has(text.toLowerCase()) || /^\[CVE-\d{4}-\d{4,}\]\(/.test(text);
      if ((h[1] === '###' || h[1] === '####') && !known) unknown.add(`heading:${text}`);
      continue;
    }
    if (!inGithub || !line.startsWith('- ')) continue;
    const link = LINK.exec(line);
    const fullName = link?.[1];
    if (!fullName || !FULL_NAME.test(fullName) || !SAFE_REF.test(fullName)) {
      skipped++;
      continue;
    }
    if (seen.has(fullName)) continue;
    seen.add(fullName);
    refs.push(fullName);
  }
  const records: SignalRecord[] = refs.slice(0, MAX_POC_PER_CVE).map((ref) => ({
    vulnKey,
    kind: 'poc',
    source: 'trickest-cve',
    ref,
    firstSeen,
    url: `https://github.com/${ref}`,
  }));
  return { records, unknownFields: [...unknown], skipped };
}

export const parse = (input: unknown): ParseResult<SignalRecord> & { skipped: number } =>
  parseTrickestCve(input, new Date());
