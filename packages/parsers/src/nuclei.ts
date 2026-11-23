import type { ParseResult, SignalRecord } from '@ti/core/types';
import { cveRefs, SAFE_REF } from './exploit-db';

/**
 * Nuclei template parser. Reads only the top of the template with a line-based reader (no YAML
 * library): the top-level `id:` and the `info:` block. The request section is never read. Worker-safe.
 */

const KNOWN_INFO = new Set([
  'name',
  'author',
  'severity',
  'description',
  'impact',
  'remediation',
  'reference',
  'classification',
  'metadata',
  'tags',
]);

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

const indentOf = (line: string) => line.length - line.trimStart().length;
const isBlank = (line: string) => line.trim() === '' || line.trimStart().startsWith('#');

function unquote(s: string): string {
  let t = s.trim();
  // A trailing ` # comment` outside quotes.
  if (!/^["']/.test(t)) t = t.replace(/\s+#.*$/, '');
  const m = /^(["'])(.*)\1$/.exec(t);
  return (m ? (m[2] as string) : t).trim();
}

/** `a`, `"a"`, `a,b` or `[a, b]` -> items. */
function inlineItems(value: string): string[] {
  let v = value.trim();
  if (!/^["']/.test(v)) v = v.replace(/\s+#.*$/, '').trim();
  if (v.startsWith('[') && v.endsWith(']')) v = v.slice(1, -1);
  return v.split(',').map(unquote);
}

function unwrap(input: unknown): { text: string; path?: string } | null {
  if (typeof input === 'string') return { text: input };
  if (isObj(input) && 'text' in input && 'path' in input) {
    if (input.status === 'removed' || input.text === null || input.text === undefined) return null;
    if (typeof input.text !== 'string' || typeof input.path !== 'string')
      throw new Error('nuclei: GitFile needs a string path and text');
    return { text: input.text, path: input.path };
  }
  throw new Error('nuclei: input must be a GitFile or the template text');
}

export function parseNucleiTemplate(input: unknown, today: Date): ParseResult<SignalRecord> {
  const file = unwrap(input);
  if (!file) return { records: [], unknownFields: [] };
  const lines = file.text.split(/\r?\n/);

  let id: string | undefined;
  let infoAt = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (isBlank(line) || indentOf(line) > 0) continue;
    const m = /^([A-Za-z_][\w-]*):(.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === 'id' && id === undefined) id = unquote(m[2] as string);
    else if (m[1] === 'info' && infoAt < 0) infoAt = i;
    // The first top-level key after `info` ends the block; the request section is never reached.
    else if (infoAt >= 0) break;
    if (id !== undefined && infoAt >= 0 && i > infoAt) break;
  }
  if (!id) throw new Error('nuclei: template has no id');

  const unknown = new Set<string>();
  const cves: string[] = [];
  if (infoAt >= 0) {
    // The info block: lines up to the next top-level key.
    const block: string[] = [];
    for (let i = infoAt + 1; i < lines.length; i++) {
      const line = lines[i] as string;
      if (!isBlank(line) && indentOf(line) === 0) break;
      block.push(line);
    }
    const first = block.find((l) => !isBlank(l));
    const base = first ? indentOf(first) : 0;
    let inClassification = false;
    for (let i = 0; i < block.length; i++) {
      const line = block[i] as string;
      if (isBlank(line)) continue;
      const ind = indentOf(line);
      const m = /^([\w-]+):(.*)$/.exec(line.trimStart());
      if (ind === base && m) {
        const key = m[1] as string;
        if (!KNOWN_INFO.has(key)) unknown.add(`info.${key}`);
        inClassification = key === 'classification';
        continue;
      }
      if (!inClassification || ind <= base || !m || m[1] !== 'cve-id') continue;
      const rest = (m[2] as string).trim();
      if (rest !== '' && !rest.startsWith('#')) cves.push(...inlineItems(rest));
      else {
        for (let j = i + 1; j < block.length; j++) {
          const next = block[j] as string;
          if (isBlank(next)) continue;
          const item = /^\s*-\s+(.*)$/.exec(next);
          if (!item || indentOf(next) < ind) break;
          cves.push(unquote(item[1] as string));
        }
      }
    }
  }

  const vulnKeys = cveRefs(cves);
  if (vulnKeys.length === 0 || !SAFE_REF.test(id)) return { records: [], unknownFields: [...unknown] };
  const path = file.path;
  const url =
    path !== undefined && /^[\w./-]+$/.test(path) && !path.split('/').includes('..')
      ? `https://github.com/projectdiscovery/nuclei-templates/blob/main/${path}`
      : undefined;
  const firstSeen = today.toISOString().slice(0, 10);
  const records: SignalRecord[] = vulnKeys.map((vulnKey) => ({
    vulnKey,
    kind: 'detection',
    source: 'nuclei-templates',
    ref: id as string,
    firstSeen,
    ...(url ? { url } : {}),
  }));
  return { records, unknownFields: [...unknown] };
}

export const parse = (input: unknown): ParseResult<SignalRecord> => parseNucleiTemplate(input, new Date());
