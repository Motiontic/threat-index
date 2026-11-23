import type { Cursor } from '@ti/core/types';
import { PatternError } from './errors';
import { request } from './http';
import { buildReceipt } from './receipt';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult, type RawItem } from './types';
import { heavyResult, jobKind, pickNew, pullBlock, reasonOf, unchanged } from './util';

type Row = Record<string, string>;

/** Attributes whose values are URLs, made absolute against the page's own URL. */
const URL_ATTRS = new Set(['href', 'src', 'action', 'cite', 'poster', 'data']);

/** Rows of the page: `item` starts a row, each field selector fills it. Needs `HTMLRewriter` (Workers). */
export async function parseRows(
  html: string,
  cfg: NonNullable<PatternContext['source']['pull']>['page'] & object,
): Promise<Row[]> {
  const Rewriter = (globalThis as { HTMLRewriter?: typeof HTMLRewriter }).HTMLRewriter;
  if (!Rewriter) throw new PatternError('HTMLRewriter is not available in this runtime', 'runtime');

  const rows: Row[] = [];
  let row: Row | null = null;
  const rewriter = new Rewriter().on(cfg.item, {
    element() {
      row = {};
      rows.push(row);
    },
  });

  for (const [name, spec] of Object.entries(cfg.fields)) {
    const selector = typeof spec === 'string' ? spec : spec.selector;
    const attr = typeof spec === 'string' ? null : spec.attr;
    let capturing: Row | null = null;
    let buffer = '';
    rewriter.on(selector, {
      element(el) {
        const target = row;
        if (!target || name in target) return;
        if (attr) {
          const v = el.getAttribute(attr);
          if (v === null) return;
          const value = decodeEntities(v);
          target[name] = URL_ATTRS.has(attr.toLowerCase()) ? resolve(value, cfg.url) : value.trim();
          return;
        }
        capturing = target;
        buffer = '';
        el.onEndTag(() => {
          if (capturing) capturing[name] = decodeEntities(buffer).replace(/\s+/g, ' ').trim();
          capturing = null;
        });
      },
      text(t) {
        if (capturing) buffer += t.text;
      },
    });
  }

  await rewriter.transform(new Response(html)).arrayBuffer();
  const out = rows.filter((r) => (r[cfg.key] ?? '') !== '');
  for (const r of out) for (const k of Object.keys(r)) if (r[k] === '') delete r[k];
  return out;
}

const NAMED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

/** HTMLRewriter hands over text and attributes as written, so `&amp;` is still encoded. */
export function decodeEntities(text: string): string {
  return text.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]+));/g, (m, dec, hex, name) => {
    if (name) return NAMED[name] ?? m;
    const code = dec ? Number(dec) : Number.parseInt(hex, 16);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
  });
}

function resolve(value: string, base: string): string {
  try {
    return new URL(value.trim(), base).href;
  } catch {
    return value.trim();
  }
}

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const cfg = pullBlock(ctx, 'page', { allowLinkOnly: true });
  if (!ctx.cursor?.etag) return 'changed';
  const res = await request(ctx, cfg.url, { validator: ctx.cursor.etag, accept: 'text/html' });
  if (res.notModified) return 'unchanged';
  const rows = await parseRows(res.text, cfg);
  const order = cfg.order ?? 'newest-first';
  const newest = order === 'newest-first' ? rows[0] : rows[rows.length - 1];
  return newest && newest[cfg.key] === ctx.cursor.value ? 'unchanged' : 'changed';
}

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'page', { allowLinkOnly: true });
  const res = await request(ctx, cfg.url, { validator: ctx.cursor?.etag ?? null, accept: 'text/html' });
  if (res.notModified) return unchanged(ctx);

  const rows = (await parseRows(res.text, cfg)).map((r) => ({ key: r[cfg.key] as string, row: r }));
  const picked = pickNew(rows, cfg.order ?? 'newest-first', ctx.cursor?.value ?? null, MAX_ITEMS_PER_STEP);
  if (picked.gap)
    ctx.log('page: the cursor key is not on the page, rows may have been missed', { source: ctx.source.id });
  if (picked.fresh.length === 0) return unchanged(ctx);

  if (ctx.source.heavy)
    return heavyResult(ctx, cursorOf(picked.newestKey as string, res.validator), {
      kind: jobKind(ctx),
      url: cfg.url,
      reason: reasonOf(ctx.cursor?.value, picked.newestKey as string),
    });

  const isLink = ctx.source.licence === 'link';
  const items: RawItem[] = picked.fresh.map((e) => ({
    id: e.key,
    body: isLink
      ? { id: e.key, title: e.row.title ?? '', date: e.row.date ?? '', link: e.row.link ?? '' }
      : e.row,
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
    nextCursor: cursorOf(last.key, picked.more ? null : res.validator),
    more: picked.more,
  };
}

const cursorOf = (key: string, etag: string | null): Cursor => ({
  kind: 'version',
  value: key,
  ...(etag ? { etag } : {}),
});
