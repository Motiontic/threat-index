import type { Cursor } from '@ti/core/types';
import { PatternError } from './errors';
import { request } from './http';
import { buildReceipt } from './receipt';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult, type RawItem } from './types';
import {
  asId,
  cutDocument,
  fnv1a,
  getPath,
  heavyResult,
  jobKind,
  parseCsv,
  parseJson,
  pullBlock,
  reasonOf,
  tryJsonObject,
  unchanged,
} from './util';

export const MAX_FINGERPRINT_ITEMS = 5000;

interface State {
  /** The version (or validator) these hashes belong to; null while a run is still in progress. */
  v: string | null;
  h: Record<string, string>;
}

function readState(cursor: Cursor | null): State | null {
  if (!cursor) return null;
  const o = tryJsonObject(cursor.value);
  if (!o || Array.isArray(o) || typeof o.h !== 'object' || o.h === null) return null;
  return { v: typeof o.v === 'string' ? o.v : null, h: o.h as Record<string, string> };
}

function versionOf(text: string, pattern: string): string {
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch (cause) {
    throw new PatternError('pull.fingerprint.version.pattern is not a valid regex', 'not-configured', {
      cause,
    });
  }
  const m = re.exec(text);
  if (!m?.[1]) throw new PatternError('version not found in the file head', 'format');
  return m[1];
}

/** The file's current version (or validator), cheaply. `null` validator = the server gave none. */
async function current(ctx: PatternContext): Promise<{ v: string | null; validator: string | null }> {
  const cfg = pullBlock(ctx, 'fingerprint');
  if (cfg.version) {
    const res = await request(ctx, cfg.url, { range: { start: 0, end: cfg.version.bytes - 1 } });
    return { v: versionOf(res.text, cfg.version.pattern), validator: res.validator };
  }
  const res = await request(ctx, cfg.url, { method: 'HEAD', validator: ctx.cursor?.etag ?? null });
  return { v: res.validator, validator: res.validator };
}

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const cfg = pullBlock(ctx, 'fingerprint');
  const state = readState(ctx.cursor);
  if (!state || state.v === null) return 'changed';
  const cfgHasVersion = Boolean(cfg.version);
  if (!cfgHasVersion) {
    const res = await request(ctx, cfg.url, { method: 'HEAD', validator: ctx.cursor?.etag ?? null });
    if (res.notModified) return 'unchanged';
    return res.validator !== null && res.validator === state.v ? 'unchanged' : 'changed';
  }
  const now = await current(ctx);
  return now.v === state.v ? 'unchanged' : 'changed';
}

const cursorFor = (ctx: PatternContext, state: State, validator: string | null): Cursor => ({
  kind: pullBlock(ctx, 'fingerprint').version ? 'version' : 'etag',
  value: JSON.stringify(state),
  ...(validator ? { etag: validator } : {}),
});

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'fingerprint');
  const state = readState(ctx.cursor) ?? { v: null, h: {} };
  const settledV = state.v;

  if (ctx.source.heavy) {
    const now = await current(ctx);
    if (settledV !== null && now.v !== null && now.v === settledV) return unchanged(ctx);
    return heavyResult(ctx, cursorFor(ctx, { v: now.v, h: {} }, now.validator), {
      kind: jobKind(ctx),
      url: cfg.url,
      reason: reasonOf(settledV, now.v ?? 'unknown'),
    });
  }

  let res: Awaited<ReturnType<typeof request>>;
  try {
    res = await request(ctx, cfg.url, { validator: settledV !== null ? (ctx.cursor?.etag ?? null) : null });
  } catch (err) {
    if (err instanceof PatternError && err.code === 'too-large') return tooLarge(ctx, settledV);
    throw err;
  }
  if (res.notModified) return unchanged(ctx);

  const entries = split(res.text, cfg);
  if (entries.length > MAX_FINGERPRINT_ITEMS) return tooLarge(ctx, settledV);

  const doc =
    cfg.format === 'json' && cfg.itemsPath ? parseJson<unknown>(res.text, 'fingerprint file') : null;
  const hashes: Record<string, string> = {};
  const changed: Array<{ key: string; body: unknown }> = [];
  for (const e of entries) {
    const hash = fnv1a(JSON.stringify(e.value));
    hashes[e.key] = hash;
    if (state.h[e.key] !== hash)
      changed.push({ key: e.key, body: doc ? cutDocument(doc, cfg.itemsPath, e.value) : e.value });
  }

  const take = changed.slice(0, MAX_ITEMS_PER_STEP);
  const more = changed.length > take.length;
  const items: RawItem[] = take.map((c) => ({ id: c.key, body: c.body }));

  let nextCursor: Cursor;
  if (more) {
    // Mid-run: remember what has been returned. `v: null` marks the run as unfinished.
    const h = { ...state.h };
    for (const c of take) h[c.key] = hashes[c.key] as string;
    nextCursor = { kind: cursorFor(ctx, state, null).kind, value: JSON.stringify({ v: null, h }) };
  } else {
    const v = cfg.version
      ? versionOf(res.text.slice(0, cfg.version.bytes), cfg.version.pattern)
      : res.validator;
    nextCursor = cursorFor(ctx, { v, h: hashes }, res.validator);
    if (items.length === 0 && ctx.cursor && nextCursor.value === ctx.cursor.value) return unchanged(ctx);
  }
  return {
    items,
    receipt: buildReceipt(
      ctx,
      items.length
        ? [
            {
              url: res.url,
              status: res.status,
              contentType: res.headers.get('content-type') ?? '',
              body: res.text,
            },
          ]
        : [],
    ),
    nextCursor,
    more,
  };
}

function tooLarge(ctx: PatternContext, settledV: string | null): PatternResult {
  const cfg = pullBlock(ctx, 'fingerprint');
  // The file is too big to read here. The job loads it; the cursor keeps no hashes.
  return heavyResult(ctx, cursorFor(ctx, { v: settledV, h: {} }, null), {
    kind: 'big-file',
    url: cfg.url,
    reason: `${cfg.url} is over the size limit`,
  });
}

function split(
  text: string,
  cfg: NonNullable<PatternContext['source']['pull']>['fingerprint'] & object,
): Array<{ key: string; value: unknown }> {
  const out: Array<{ key: string; value: unknown }> = [];
  if (cfg.format === 'csv') {
    const rows = parseCsv(text);
    const header = rows.shift();
    if (!header) throw new PatternError('empty CSV', 'format');
    const col = header.indexOf(cfg.key);
    if (col < 0) throw new PatternError(`CSV has no ${cfg.key} column`, 'format');
    for (const r of rows) {
      const key = r[col];
      if (!key) continue;
      out.push({ key, value: Object.fromEntries(header.map((h, i) => [h, r[i] ?? ''])) });
    }
    return out;
  }
  const doc = parseJson<unknown>(text, 'fingerprint file');
  const list = cfg.itemsPath ? getPath(doc, cfg.itemsPath) : doc;
  if (!Array.isArray(list)) throw new PatternError('fingerprint file has no entries array', 'format');
  for (const entry of list) {
    const key = asId(getPath(entry, cfg.key));
    if (key !== null) out.push({ key, value: entry });
  }
  return out;
}
