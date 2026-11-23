import type { Cursor } from '@ti/core/types';
import { XMLParser } from 'fast-xml-parser';
import { PatternError } from './errors';
import { request } from './http';
import { buildReceipt } from './receipt';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult, type RawItem } from './types';
import {
  heavyResult,
  httpUrl,
  jobKind,
  pickNew,
  pullBlock,
  reasonOf,
  rejectXmlEntities,
  unchanged,
} from './util';

/** What a link-only source keeps of an entry. */
export interface LinkOnlyItem {
  id: string;
  title: string;
  date: string;
  link: string;
}

type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  processEntities: true,
  parseTagValue: false,
});

const arr = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

/** Text of a node: a string, or `#text` next to attributes. */
export function textOf(v: unknown): string {
  if (typeof v === 'string') return v.trim();
  if (typeof v === 'number') return String(v);
  if (v && typeof v === 'object' && '#text' in v) return textOf((v as Node)['#text']);
  return '';
}

/** RSS `<link>text</link>`, RDF the same, Atom `<link href=...>` (prefer rel=alternate). */
function linkOf(item: Node): string {
  const links = arr(item.link);
  for (const l of links) {
    if (typeof l === 'string') return l.trim();
    if (l && typeof l === 'object') {
      const n = l as Node;
      if (n['@_href'] && (!n['@_rel'] || n['@_rel'] === 'alternate')) return String(n['@_href']);
    }
  }
  for (const l of links) {
    if (l && typeof l === 'object' && (l as Node)['@_href']) return String((l as Node)['@_href']);
    const t = textOf(l);
    if (t) return t;
  }
  return '';
}

function keyOf(item: Node): string {
  return textOf(item.guid) || textOf(item.id) || textOf(item['@_rdf:about']) || linkOf(item);
}

/** Entries of an RSS 2.0, RSS 1.0 (RDF) or Atom document, in document order. */
export function parseFeed(xml: string): Node[] {
  rejectXmlEntities(xml);
  let doc: Node;
  try {
    doc = parser.parse(xml) as Node;
  } catch (cause) {
    throw new PatternError('feed is not valid XML', 'format', { cause });
  }
  const rss = doc.rss as Node | undefined;
  if (rss) return arr((rss.channel as Node | undefined)?.item) as Node[];
  const rdf = doc['rdf:RDF'] as Node | undefined;
  if (rdf) return arr(rdf.item) as Node[];
  const atom = doc.feed as Node | undefined;
  if (atom) return arr(atom.entry) as Node[];
  throw new PatternError('not an RSS, RDF or Atom feed', 'format');
}

/**
 * A copy of the entry whose links are absolute http(s) only: RSS `<link>` text and Atom
 * `<link href>`. Other links are removed and reported through `onDroppedLink`.
 */
export function sanitizeLinks(item: Node, onDroppedLink?: () => void): Node {
  if (item.link === undefined) return item;
  const kept: unknown[] = [];
  for (const l of arr(item.link)) {
    if (l && typeof l === 'object' && '@_href' in l) {
      const n = l as Node;
      const href = httpUrl(String(n['@_href']));
      if (href === null) onDroppedLink?.();
      else kept.push({ ...n, '@_href': href });
    } else {
      const t = textOf(l);
      if (t === '') continue;
      const href = httpUrl(t);
      if (href === null) onDroppedLink?.();
      else kept.push(href);
    }
  }
  const { link: _drop, ...rest } = item;
  if (kept.length === 0) return rest;
  return { ...rest, link: kept.length === 1 ? kept[0] : kept };
}

export function linkOnly(item: Node, id: string, onDroppedLink?: () => void): LinkOnlyItem {
  const raw = linkOf(item);
  let link = '';
  if (raw) {
    // Only absolute http(s) links survive; javascript:, data: and the like are dropped.
    link = httpUrl(raw) ?? '';
    if (!link) onDroppedLink?.();
  }
  const date =
    textOf(item.pubDate) || textOf(item.updated) || textOf(item.published) || textOf(item['dc:date']);
  return { id, title: textOf(item.title), date, link };
}

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const cfg = pullBlock(ctx, 'feed', { allowLinkOnly: true });
  // No cursor, or a mid-run one (no validator yet): there is more to do.
  if (!ctx.cursor?.etag) return 'changed';
  const res = await request(ctx, cfg.url, {
    validator: ctx.cursor.etag,
    accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml',
  });
  if (res.notModified) return 'unchanged';
  const entries = parseFeed(res.text);
  const order = cfg.order ?? 'newest-first';
  const newest = order === 'newest-first' ? entries[0] : entries[entries.length - 1];
  return newest && keyOf(newest) === ctx.cursor.value ? 'unchanged' : 'changed';
}

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'feed', { allowLinkOnly: true });
  const res = await request(ctx, cfg.url, {
    validator: ctx.cursor?.etag ?? null,
    accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml',
  });
  if (res.notModified) return unchanged(ctx);

  const entries = parseFeed(res.text)
    .map((item) => ({ key: keyOf(item), item }))
    .filter((e) => e.key);
  const picked = pickNew(entries, cfg.order ?? 'newest-first', ctx.cursor?.value ?? null, MAX_ITEMS_PER_STEP);
  if (picked.gap)
    ctx.log('feed: the cursor key is not in the feed, entries may have been missed', {
      source: ctx.source.id,
    });
  if (picked.fresh.length === 0) return unchanged(ctx);

  if (ctx.source.heavy)
    return heavyResult(ctx, versionCursor(picked.newestKey as string, res.validator), {
      kind: jobKind(ctx),
      url: cfg.url,
      reason: reasonOf(ctx.cursor?.value, picked.newestKey as string),
    });

  const isLink = ctx.source.licence === 'link';
  const items: RawItem[] = picked.fresh.map((e) => ({
    id: e.key,
    body: isLink
      ? linkOnly(e.item, e.key, () =>
          ctx.log('feed: dropped a link that is not http(s)', { source: ctx.source.id }),
        )
      : sanitizeLinks(e.item, () =>
          ctx.log('feed: dropped a link that is not http(s)', { source: ctx.source.id }),
        ),
  }));
  const receipt = buildReceipt(
    ctx,
    isLink
      ? [
          {
            url: res.url,
            status: res.status,
            contentType: 'application/json',
            body: JSON.stringify(items.map((i) => i.body)),
          },
        ]
      : [
          {
            url: res.url,
            status: res.status,
            contentType: res.headers.get('content-type') ?? '',
            body: res.text,
          },
        ],
  );
  const last = picked.fresh[picked.fresh.length - 1] as { key: string };
  return {
    items,
    receipt,
    nextCursor: versionCursor(last.key, picked.more ? null : res.validator),
    more: picked.more,
  };
}

const versionCursor = (key: string, etag: string | null): Cursor => ({
  kind: 'version',
  value: key,
  ...(etag ? { etag } : {}),
});
