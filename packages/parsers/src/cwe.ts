import type { ParseResult, TechniqueRecord } from '@ti/core/types';
import { clip, SUMMARY_MAX } from './cve-json5';

/**
 * MITRE's two XML catalogues, by root element: `Weakness_Catalog` (CWE) and `Attack_Pattern_Catalog`
 * (CAPEC). No XML library: a small scanner reads each entry's attributes, description and relations.
 * Runs in the E2B big-file job, but is Worker-safe all the same.
 */

interface Kind {
  entry: string;
  related: string;
  idAttr: string;
  framework: 'cwe' | 'capec';
  prefix: string;
}

const KINDS: Record<string, Kind> = {
  Weakness_Catalog: {
    entry: 'Weakness',
    related: 'Related_Weakness',
    idAttr: 'CWE_ID',
    framework: 'cwe',
    prefix: 'CWE',
  },
  Attack_Pattern_Catalog: {
    entry: 'Attack_Pattern',
    related: 'Related_Attack_Pattern',
    idAttr: 'CAPEC_ID',
    framework: 'capec',
    prefix: 'CAPEC',
  },
};

const ATTRS = '((?:\\s+[\\w:.-]+\\s*=\\s*(?:"[^"]*"|\'[^\']*\'))*)\\s*(\\/?)>';
const ATTR = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
const ENTITY = /&(?:#(\d+)|#x([0-9a-fA-F]+)|(lt|gt|amp|quot|apos));/g;
const NAMED: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

function decode(s: string): string {
  return s.replace(ENTITY, (whole, dec?: string, hex?: string, name?: string) => {
    if (name) return NAMED[name] ?? whole;
    const cp = dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex ?? '', 16);
    return cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : whole;
  });
}

function attrs(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of raw.matchAll(ATTR)) out[m[1] as string] = decode((m[2] ?? m[3]) as string);
  return out;
}

/** Tags stripped first, then entities decoded, so an escaped `&lt;b&gt;` stays as text. */
function plain(xml: string): string {
  return decode(
    xml
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (_, t: string) =>
        t.replace(/&/g, '&amp;').replace(/</g, '&lt;'),
      )
      .replace(/<[^>]*>/g, ' '),
  );
}

export function parseMitreCatalog(input: unknown): ParseResult<TechniqueRecord> & { version: string } {
  if (typeof input !== 'string') throw new Error('cwe: expected XML text');
  const rootMatch = /<([A-Za-z_][\w.-]*)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*\/?>/.exec(input);
  const kind = rootMatch ? KINDS[rootMatch[1] as string] : undefined;
  if (!rootMatch || !kind)
    throw new Error(
      `cwe: unexpected root element <${rootMatch?.[1] ?? 'none'}>, want Weakness_Catalog or Attack_Pattern_Catalog`,
    );
  const version = attrs(rootMatch[2] ?? '').Version;
  if (!version) throw new Error('cwe: catalogue root has no Version attribute');

  const open = new RegExp(`<${kind.entry}${ATTRS}`, 'g');
  const close = `</${kind.entry}>`;
  const relation = new RegExp(`<${kind.related}${ATTRS}`, 'g');
  const records: TechniqueRecord[] = [];

  for (let m = open.exec(input); m !== null; m = open.exec(input)) {
    const a = attrs(m[1] ?? '');
    let body = '';
    if (m[2] !== '/') {
      const end = input.indexOf(close, open.lastIndex);
      if (end < 0) throw new Error(`cwe: unterminated <${kind.entry}> element`);
      body = input.slice(open.lastIndex, end);
      open.lastIndex = end + close.length;
    }
    if (a.Status === 'Deprecated' || !a.ID || !a.Name) continue;

    const desc = /<Description(?:\s[^>]*)?>([\s\S]*?)<\/Description>/.exec(body);
    const summary = desc ? clip(plain(desc[1] as string), SUMMARY_MAX) : '';

    let parent: string | undefined;
    let first: string | undefined;
    for (const r of body.matchAll(relation)) {
      const ra = attrs(r[1] ?? '');
      const target = ra[kind.idAttr];
      if (ra.Nature !== 'ChildOf' || !target) continue;
      first ??= target;
      if (kind.framework === 'capec') break;
      if (ra.View_ID === '1000' && ra.Ordinal === 'Primary') {
        parent = target;
        break;
      }
    }
    const parentId = parent ?? first;

    records.push({
      id: `${kind.prefix}-${a.ID}`,
      framework: kind.framework,
      name: a.Name,
      ...(summary ? { summary } : {}),
      ...(parentId ? { parent: `${kind.prefix}-${parentId}` } : {}),
    });
  }

  return { records, unknownFields: [], version };
}

/** The parser-module contract: `@ti/parsers/cwe` exports `parse`. */
export const parse = parseMitreCatalog;
