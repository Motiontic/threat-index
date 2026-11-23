import type { AdvisoryRecord, ParseResult } from '@ti/core/types';
import { cveList, isoMs, perCve } from './cert-common';

/**
 * JVN iPedia "Update Entry" feed (`https://jvndb.jvn.jp/en/rss/jvndb.rdf`, about 1.4 MB, 500 items). The input is
 * the whole RDF document as a string: the E2B first-load job's body. No XML library: a small scanner like the one in
 * `cwe.ts`. IDs, CVEs, dates and the link only; titles, descriptions, CPEs and CVSS are never copied.
 * No Node-only imports: runs in Workers and E2B.
 */

const KNOWN = new Set([
  'title',
  'link',
  'description',
  'sec:identifier',
  'sec:references',
  'sec:cpe',
  'sec:cvss',
  'dc:date',
  'dcterms:issued',
  'dcterms:modified',
]);
const IDENTIFIER = /^JVNDB-(\d{4})-\d{6}$/;
const JVN_HOST = 'https://jvndb.jvn.jp/';

const ITEM = /<item(?=[\s>])[^>]*>([\s\S]*?)<\/item>/g;
const TAG = /<(\/)?([A-Za-z_][\w:.-]*)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/)?>/g;
const ATTR = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
const ENTITY = /&(?:#(\d+)|#x([0-9a-fA-F]+)|(lt|gt|amp|quot|apos));/g;
const NAMED: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

/** Decodes the five XML entities and numeric references; anything else stays as written. */
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

interface Child {
  name: string;
  attrs: Record<string, string>;
  text: string;
}

/** The direct children of one item body, in order. Text is the child's inner text, entities decoded. */
function children(body: string): Child[] {
  const clean = body
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (_, t: string) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;'));
  const out: Child[] = [];
  let depth = 0;
  let cur: { name: string; attrs: string; from: number } | null = null;
  for (const m of clean.matchAll(TAG)) {
    const [whole, closing, name, rawAttrs, selfClose] = m as unknown as [
      string,
      string | undefined,
      string,
      string,
      string | undefined,
    ];
    const at = m.index as number;
    if (closing) {
      depth--;
      if (depth === 0 && cur && cur.name === name) {
        out.push({
          name,
          attrs: attrs(cur.attrs),
          text: decode(clean.slice(cur.from, at).replace(/<[^>]*>/g, '')),
        });
        cur = null;
      }
      if (depth < 0) depth = 0;
    } else if (selfClose) {
      if (depth === 0) out.push({ name, attrs: attrs(rawAttrs), text: '' });
    } else {
      if (depth === 0) cur = { name, attrs: rawAttrs, from: at + whole.length };
      depth++;
    }
  }
  return out;
}

export function parseJvn(input: unknown): ParseResult<AdvisoryRecord> {
  if (typeof input !== 'string') throw new Error('jvn: expected the RDF document as text');
  if (!input.includes('<rdf:RDF')) throw new Error('jvn: not an RDF document (no <rdf:RDF root)');
  if (/<!(?:DOCTYPE|ENTITY)/i.test(input))
    throw new Error('jvn: DOCTYPE and ENTITY declarations are not accepted');

  const unknown = new Set<string>();
  const records: AdvisoryRecord[] = [];

  for (const m of input.matchAll(ITEM)) {
    const kids = children(m[1] as string);
    for (const k of kids) if (!KNOWN.has(k.name)) unknown.add(`item.${k.name}`);
    const first = (name: string) => kids.find((k) => k.name === name)?.text.trim() ?? '';

    const identifier = first('sec:identifier');
    const idMatch = IDENTIFIER.exec(identifier);
    if (!idMatch) {
      unknown.add('item.sec:identifier');
      continue;
    }
    const issued = isoMs(first('dcterms:issued'));
    const modified = isoMs(first('dcterms:modified')) ?? isoMs(first('dc:date'));
    if (modified === null) {
      unknown.add('item.dcterms:modified');
      continue;
    }
    const cves = cveList(
      kids.filter((k) => k.name === 'sec:references' && k.attrs.source === 'CVE').map((k) => k.attrs.id),
    );
    const link = first('link');
    records.push(
      ...perCve(identifier, cves, {
        source: 'jvn',
        status: 'active',
        ...(issued ? { published: issued } : {}),
        modified,
        url: link.startsWith(JVN_HOST) ? link : `${JVN_HOST}en/contents/${idMatch[1]}/${identifier}.html`,
      }),
    );
  }
  return { records, unknownFields: [...unknown] };
}

/** The parser-module contract: `@ti/parsers/jvn` exports `parse`. */
export const parse = parseJvn;
