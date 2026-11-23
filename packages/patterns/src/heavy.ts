import type { Cursor } from '@ti/core/types';
import { PatternError } from './errors';
import { request } from './http';
import type { PatternContext, PatternResult } from './types';
import { heavyResult, jobKind, pullBlock, reasonOf, unchanged } from './util';

const DEFAULT_VERSION_BYTES = 4096;

interface Seen {
  value: string;
  etag: string | null;
  kind: Cursor['kind'];
}

/** The remote's current version or validator. Never parses the file. */
async function current(ctx: PatternContext): Promise<Seen> {
  const cfg = pullBlock(ctx, 'heavy');
  if (cfg.version) {
    const bytes = cfg.version.bytes ?? DEFAULT_VERSION_BYTES;
    const res = await request(ctx, cfg.version.url, { range: { start: 0, end: bytes - 1 } });
    let re: RegExp;
    try {
      re = new RegExp(cfg.version.pattern);
    } catch (cause) {
      throw new PatternError('pull.heavy.version.pattern is not a valid regex', 'not-configured', { cause });
    }
    const m = re.exec(res.text);
    if (!m?.[1]) throw new PatternError('version not found', 'format');
    return { value: m[1], etag: res.validator, kind: 'version' };
  }
  const res = await request(ctx, cfg.url, { method: 'HEAD', validator: ctx.cursor?.etag ?? null });
  const validator = res.validator ?? ctx.cursor?.etag ?? null;
  if (!validator)
    throw new PatternError('no version pattern and the server sends no validator', 'not-configured');
  return { value: validator, etag: validator, kind: 'etag' };
}

const same = (ctx: PatternContext, seen: Seen) => ctx.cursor !== null && ctx.cursor.value === seen.value;

export async function check(ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  const seen = await current(ctx);
  return same(ctx, seen) ? 'unchanged' : 'changed';
}

export async function fetch(ctx: PatternContext): Promise<PatternResult> {
  const cfg = pullBlock(ctx, 'heavy');
  const seen = await current(ctx);
  if (same(ctx, seen)) return unchanged(ctx);
  return heavyResult(
    ctx,
    { kind: seen.kind, value: seen.value, ...(seen.etag ? { etag: seen.etag } : {}) },
    { kind: jobKind(ctx), url: cfg.url, reason: reasonOf(ctx.cursor?.value, seen.value) },
  );
}
