import { compareLines, type Pair, readPair, refKept } from '@ti/core/changelist';
import type { Cursor } from '@ti/core/types';
import { PatternError } from './errors';
import { request } from './http';
import { buildReceipt, type ReceiptPart } from './receipt';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult, type RawItem } from './types';
import {
  fillTemplate,
  heavyResult,
  jobKind,
  mapUntilTooLarge,
  parseCsvLine,
  pullBlock,
  reasonOf,
  unchanged,
} from './util';

export interface ChangeItem {
  ref: string;
  time: string;
  text: string | null;
}

export const MAX_RANGE_READS = 4;
const DEFAULT_RANGE_BYTES = 65_536;

interface Line {
  time: string;
  ref: string;
  ms: number;
}

function readCursor(cursor: Cursor | null): Pair | null {
  return cursor ? readPair(cursor.value) : null;
}

const cmp = compareLines;
const lineOf = (p: Pair): Line => ({ time: p[0], ref: p[1], ms: Date.parse(p[0]) });
/** `a`, or `b` when it is later. */
const laterOf = (a: Line, b: Line | null): Line => (b && cmp(b, a) > 0 ? b : a);

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const cfg = pullBlock(ctx, 'changelist');
  // No cursor, or a mid-run one (no validator yet): there is more to do.
  if (!readCursor(ctx.cursor) || !ctx.cursor?.etag) return 'changed';
  const res = await request(ctx, cfg.listUrl, { method: 'HEAD', validator: ctx.cursor.etag });
  if (res.notModified || (res.validator && res.validator === ctx.cursor.etag)) return 'unchanged';
  return 'changed';
}

interface Scan {
  fresh: Line[];
  newest: Line | null;
  validator: string | null;
  skipped: number;
  /** Lines the `refPrefixes` filter dropped. */
  filtered: number;
  /** The boundary (or the end of the list) was reached within the allowed reads. */
  complete: boolean;
}

/** Reads the newest-first list with ranges until a line older than the cursor. */
async function scan(ctx: PatternContext, cursor: Pair | null): Promise<Scan> {
  const cfg = pullBlock(ctx, 'changelist');
  const size = cfg.rangeBytes ?? DEFAULT_RANGE_BYTES;
  const cursorMs = cursor ? Date.parse(cursor[0]) : Number.NEGATIVE_INFINITY;
  const out: Scan = { fresh: [], newest: null, validator: null, skipped: 0, filtered: 0, complete: false };
  let carry = '';
  // One streaming decoder for every range: a character split across a boundary stays whole.
  const decoder = new TextDecoder();
  for (let i = 0; i < MAX_RANGE_READS; i++) {
    let res: Awaited<ReturnType<typeof request>>;
    try {
      res = await request(ctx, cfg.listUrl, {
        range: { start: i * size, end: (i + 1) * size - 1 },
        decoder,
      });
    } catch (err) {
      // Past the end of the list.
      if (err instanceof PatternError && err.status === 416) {
        out.complete = true;
        break;
      }
      throw err;
    }
    if (i === 0) out.validator = res.validator;
    // A server that ignores Range can only be read from the start.
    if (i > 0 && res.status === 200) return out;
    const eof = reachedEnd(res, size);
    const text = carry + res.text;
    const lines = text.split('\n');
    carry = eof ? '' : (lines.pop() ?? '');
    if (eof && lines[lines.length - 1] === '') lines.pop();
    let boundary = false;
    for (const raw of lines) {
      const line = raw.replace(/\r$/, '');
      if (!line) continue;
      const cols = parseCsvLine(line);
      const time = cols[cfg.timeColumn];
      const ref = cols[cfg.refColumn];
      const ms = time ? Date.parse(time) : Number.NaN;
      if (!time || !ref || Number.isNaN(ms)) {
        out.skipped++;
        continue;
      }
      const l = { time, ref, ms };
      if (!out.newest || cmp(l, out.newest) > 0) out.newest = l;
      if (ms < cursorMs) {
        boundary = true;
        break;
      }
      if (!refKept(ref, cfg.refPrefixes)) {
        out.filtered++;
        continue;
      }
      if (!cursor || cmp(l, lineOf(cursor)) > 0) out.fresh.push(l);
    }
    if (boundary || eof) {
      out.complete = true;
      break;
    }
  }
  if (out.skipped) ctx.log('changelist: skipped unreadable lines', { skipped: out.skipped });
  if (out.filtered) ctx.log('changelist: lines outside refPrefixes', { filtered: out.filtered });
  return out;
}

/** Whether a ranged read got the last byte of the list. */
function reachedEnd(
  res: { status: number; truncated: boolean; bytes: number; headers: Headers },
  size: number,
): boolean {
  if (res.status === 200) return !res.truncated;
  const m = /bytes (\d+)-(\d+)\/(\d+)/.exec(res.headers.get('content-range') ?? '');
  if (m) return Number(m[2]) + 1 >= Number(m[3]);
  return res.bytes < size;
}

const pairCursor = (l: Pair | Line, etag?: string | null): Cursor => {
  const pair: Pair = Array.isArray(l) ? l : [l.time, l.ref];
  return { kind: 'timestamp', value: JSON.stringify(pair), ...(etag ? { etag } : {}) };
};

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'changelist');
  const cursor = readCursor(ctx.cursor);
  const size = cfg.rangeBytes ?? DEFAULT_RANGE_BYTES;

  if (!cursor) {
    // No history is pulled in a Worker: note where the list ends today and hand off.
    const res = await request(ctx, cfg.listUrl, { range: { start: 0, end: size - 1 } });
    const first = res.text
      .split('\n')
      .map((l) => parseCsvLine(l.replace(/\r$/, '')))
      .find((c) => {
        const t = c[cfg.timeColumn];
        return Boolean(t && c[cfg.refColumn] && !Number.isNaN(Date.parse(t)));
      });
    if (!first) throw new PatternError('changelist is empty or unreadable', 'format');
    const next = pairCursor([first[cfg.timeColumn] as string, first[cfg.refColumn] as string], res.validator);
    return heavyResult(ctx, next, {
      kind: 'first-load',
      url: cfg.listUrl,
      reason: reasonOf(null, next.value),
    });
  }

  const s = await scan(ctx, cursor);
  if (!s.complete) {
    const newest = s.newest ?? cursor;
    return heavyResult(ctx, pairCursor(newest, s.validator), {
      kind: 'big-file',
      url: cfg.listUrl,
      reason: `more than ${MAX_RANGE_READS} ranges of new changes`,
    });
  }
  if (s.fresh.length === 0) {
    // Nothing kept is new, but dropped lines sit past the cursor: move it over them, so later scans stop there.
    if (s.newest && cmp(s.newest, lineOf(cursor)) > 0)
      return {
        items: [],
        receipt: null,
        nextCursor: pairCursor(s.newest, s.validator),
        more: false,
      };
    return unchanged(ctx);
  }

  const sorted = s.fresh.sort(cmp);
  if (ctx.source.heavy) {
    // The job filters the same way, so its target may be a dropped line past the newest kept one.
    const newest = laterOf(sorted[sorted.length - 1] as Line, s.newest);
    return heavyResult(ctx, pairCursor(newest, s.validator), {
      kind: jobKind(ctx),
      url: cfg.listUrl,
      reason: reasonOf(ctx.cursor?.value, pairCursor(newest).value),
    });
  }

  const take = sorted.slice(0, MAX_ITEMS_PER_STEP);
  const fetched = await mapUntilTooLarge(take, async (l) => {
    const url = fillTemplate(cfg.itemUrl, { ref: l.ref });
    try {
      const res = await request(ctx, url);
      return { line: l, url, res };
    } catch (err) {
      if (err instanceof PatternError && err.code === 'http' && (err.status === 404 || err.status === 410))
        return { line: l, url, res: null };
      throw err;
    }
  });

  if (fetched.big === 0) {
    const l = take[0] as Line;
    return heavyResult(ctx, pairCursor(l, s.validator), {
      kind: 'big-file',
      url: fillTemplate(cfg.itemUrl, { ref: l.ref }),
      reason: `${l.ref} is over the size limit`,
    });
  }

  const parts: ReceiptPart[] = [];
  const items: RawItem[] = fetched.done.map(({ line, res }) => {
    const body: ChangeItem = { ref: line.ref, time: line.time, text: res ? res.text : null };
    return { id: line.ref, body };
  });
  for (const { url, res } of fetched.done)
    if (res)
      parts.push({
        url,
        status: res.status,
        contentType: res.headers.get('content-type') ?? '',
        body: res.text,
      });

  const last = fetched.done[fetched.done.length - 1]?.line as Line;
  const more = fetched.big !== null || sorted.length > take.length;
  return {
    items,
    receipt: buildReceipt(ctx, parts),
    // When done, move over any dropped lines past the last kept one, so the next scan stops at the list's head.
    nextCursor: more ? pairCursor(last, null) : pairCursor(laterOf(last, s.newest), s.validator),
    more,
  };
}
