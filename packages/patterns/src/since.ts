import type { Cursor } from '@ti/core/types';
import { PatternError } from './errors';
import { request } from './http';
import { buildReceipt } from './receipt';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult, type RawItem } from './types';
import {
  asId,
  cutDocument,
  getPath,
  heavyResult,
  jobKind,
  parseJson,
  pullBlock,
  reasonOf,
  tryJsonObject,
  unchanged,
} from './util';

const DAY_MS = 86_400_000;

interface Mid {
  start: string;
  end: string;
  offset: number;
}

const timestamp = (value: string): Cursor => ({ kind: 'timestamp', value });

function readMid(cursor: Cursor | null): Mid | null {
  if (!cursor) return null;
  const o = tryJsonObject(cursor.value);
  if (!o || Array.isArray(o) || typeof o.start !== 'string' || typeof o.end !== 'string') return null;
  return { start: o.start, end: o.end, offset: Number(o.offset) || 0 };
}

/** The window this step reads, or null when the cursor is already at now. */
function windowOf(ctx: PatternContext, maxWindowDays: number | undefined): Mid | null {
  const mid = readMid(ctx.cursor);
  if (mid) return mid;
  if (!ctx.cursor) return null;
  const startMs = Date.parse(ctx.cursor.value);
  if (Number.isNaN(startMs)) throw new PatternError('since cursor is not a timestamp', 'format');
  const nowMs = ctx.now().getTime();
  if (startMs >= nowMs) return null;
  const endMs = maxWindowDays ? Math.min(nowMs, startMs + maxWindowDays * DAY_MS) : nowMs;
  return { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString(), offset: 0 };
}

/** `lookbackDays` gives a null cursor a starting point; otherwise a null cursor is a first load. */
function lookbackWindow(
  ctx: PatternContext,
  lookbackDays: number | undefined,
  maxWindowDays: number | undefined,
): Mid | null {
  if (!lookbackDays) return null;
  const nowMs = ctx.now().getTime();
  const startMs = nowMs - lookbackDays * DAY_MS;
  const endMs = maxWindowDays ? Math.min(nowMs, startMs + maxWindowDays * DAY_MS) : nowMs;
  return { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString(), offset: 0 };
}

async function query(ctx: PatternContext, w: Mid, limit: number) {
  const cfg = pullBlock(ctx, 'since');
  const url = new URL(cfg.url);
  url.searchParams.set(cfg.startParam, w.start);
  if (cfg.endParam) url.searchParams.set(cfg.endParam, w.end);
  url.searchParams.set(cfg.offsetParam, String(w.offset));
  url.searchParams.set(cfg.limitParam, String(limit));
  const res = await request(ctx, url.href, {
    accept: 'application/json',
    ...(cfg.auth ? { auth: cfg.auth } : {}),
  });
  const doc = parseJson<unknown>(res.text, 'since response');
  const items = getPath(doc, cfg.itemsPath);
  if (!Array.isArray(items)) throw new PatternError('since response has no items array', 'format');
  const totalRaw = cfg.totalPath ? getPath(doc, cfg.totalPath) : undefined;
  const total = typeof totalRaw === 'number' ? totalRaw : undefined;
  return { res, doc, items: items as unknown[], total };
}

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const cfg = pullBlock(ctx, 'since');
  if (!ctx.cursor || readMid(ctx.cursor)) return 'changed';
  const w = windowOf(ctx, cfg.maxWindowDays);
  if (!w) return 'unchanged';
  // A capped window has to be walked forward even when it is empty.
  if (Date.parse(w.end) < ctx.now().getTime()) return 'changed';
  const q = await query(ctx, w, 1);
  if (q.total !== undefined) return q.total > 0 ? 'changed' : 'unchanged';
  return q.items.length > 0 ? 'changed' : 'unchanged';
}

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'since');
  const nowIso = ctx.now().toISOString();

  if (!ctx.cursor) {
    const lb = lookbackWindow(ctx, cfg.lookbackDays, cfg.maxWindowDays);
    if (!lb)
      return heavyResult(ctx, timestamp(nowIso), {
        kind: 'first-load',
        url: cfg.url,
        reason: reasonOf(null, nowIso),
      });
    return page(ctx, lb);
  }

  const w = windowOf(ctx, cfg.maxWindowDays);
  if (!w) return unchanged(ctx);

  if (ctx.source.heavy) {
    // The job covers the window; the cursor moves to its end when the job completes.
    const q = await query(ctx, { ...w, offset: 0 }, 1);
    const any = q.total !== undefined ? q.total > 0 : q.items.length > 0;
    if (!any && Date.parse(w.end) >= ctx.now().getTime()) return unchanged(ctx);
    return heavyResult(ctx, timestamp(w.end), {
      kind: jobKind(ctx),
      url: cfg.url,
      reason: reasonOf(ctx.cursor.value, w.end),
    });
  }
  return page(ctx, w);
}

async function page(ctx: PatternContext, w: Mid): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'since');
  let q: Awaited<ReturnType<typeof query>>;
  try {
    q = await query(ctx, w, MAX_ITEMS_PER_STEP);
  } catch (err) {
    if (err instanceof PatternError && err.code === 'too-large')
      return heavyResult(ctx, timestamp(w.end), {
        kind: 'big-file',
        url: cfg.url,
        reason: `a page of ${cfg.url} is over the size limit`,
      });
    throw err;
  }
  const entries = q.items.slice(0, MAX_ITEMS_PER_STEP);
  const items: RawItem[] = [];
  for (const entry of entries) {
    const id = asId(getPath(entry, cfg.idPath));
    if (id === null) {
      ctx.log('since: item without an id skipped');
      continue;
    }
    items.push({ id, body: cutDocument(q.doc, cfg.itemsPath, entry) });
  }

  const reached = w.offset + entries.length;
  const finished =
    entries.length === 0 ||
    (q.total !== undefined ? reached >= q.total : entries.length < MAX_ITEMS_PER_STEP);
  const capped = Date.parse(w.end) < ctx.now().getTime();
  const nextCursor: Cursor = finished
    ? timestamp(w.end)
    : { kind: 'timestamp', value: JSON.stringify({ start: w.start, end: w.end, offset: reached }) };
  return {
    items,
    receipt: buildReceipt(
      ctx,
      items.length
        ? [
            {
              url: q.res.url,
              status: q.res.status,
              contentType: q.res.headers.get('content-type') ?? '',
              body: q.res.text,
            },
          ]
        : [],
    ),
    nextCursor,
    more: finished ? capped : true,
  };
}
