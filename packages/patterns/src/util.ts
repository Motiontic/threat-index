import type { Cursor } from '@ti/core/types';
import type { PullConfig } from '@ti/sources/pull';
import { PatternError } from './errors';
import type { HeavyJobRequest, PatternContext, PatternResult } from './types';

/** The block of `source.pull` a pattern reads, or `not-configured`. Link-only sources never reach here. */
export function pullBlock<K extends keyof PullConfig>(
  ctx: PatternContext,
  key: K,
  opts: { allowLinkOnly?: boolean } = {},
): NonNullable<PullConfig[K]> {
  const block = ctx.source.pull?.[key];
  if (!block) throw new PatternError(`${ctx.source.id}: no pull.${key} configuration`, 'not-configured');
  if (ctx.source.licence === 'link' && !opts.allowLinkOnly)
    throw new PatternError(`${ctx.source.id} is link-only`, 'not-configured');
  return block as NonNullable<PullConfig[K]>;
}

/** Nothing new: no items, no receipt, the cursor we got (`null` if we got none, which commits nothing). */
export function unchanged(ctx: PatternContext): PatternResult {
  return { items: [], receipt: null, nextCursor: ctx.cursor, more: false };
}

export function heavyResult(
  ctx: PatternContext,
  nextCursor: Cursor,
  job: Omit<HeavyJobRequest, 'sourceId'>,
): PatternResult {
  return {
    items: [],
    receipt: null,
    nextCursor,
    more: false,
    heavy: { ...job, sourceId: ctx.source.id },
  };
}

export function jobKind(ctx: PatternContext): HeavyJobRequest['kind'] {
  return ctx.source.pull?.jobKind ?? 'big-file';
}

export function reasonOf(old: string | null | undefined, now: string): string {
  const clip = (s: string) => (s.length > 80 ? `${s.slice(0, 77)}...` : s);
  return `${clip(old || 'none')} → ${clip(now)}`;
}

export function parseJson<T>(text: string, what: string): T {
  try {
    return JSON.parse(text) as T;
  } catch (cause) {
    throw new PatternError(`${what}: not valid JSON`, 'format', { cause });
  }
}

/** Settled and mid-run composite cursors are JSON objects; a SHA or a timestamp is not. */
export function tryJsonObject(value: string): Record<string, unknown> | null {
  if (!value.startsWith('{') && !value.startsWith('[')) return null;
  try {
    const v = JSON.parse(value);
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Dotted path into objects (and arrays by index). */
export function getPath(doc: unknown, path: string): unknown {
  let cur: unknown = doc;
  for (const part of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** The document with the array at `path` replaced by `[entry]`; other parts are shared, not copied. */
export function cutDocument(doc: unknown, path: string | undefined, entry: unknown): unknown {
  if (!path) return entry;
  const parts = path.split('.');
  const clone = (v: unknown): Record<string, unknown> =>
    Array.isArray(v) ? ([...v] as unknown as Record<string, unknown>) : { ...(v as Record<string, unknown>) };
  const root = clone(doc);
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i] as string;
    cur[k] = clone(cur[k]);
    cur = cur[k] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1] as string] = [entry];
  return root;
}

export function asId(v: unknown): string | null {
  if (typeof v === 'string' && v) return v;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return null;
}

/** 32-bit FNV-1a, 8 hex digits. */
export function fnv1a(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let h = 0x811c9dc5;
  for (const b of bytes) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/**
 * Fills `{name}` in a config URL template. Each value is split on `/` and each segment is encoded; `.` and
 * `..` segments are rejected, and the result must keep the template's origin.
 */
export function fillTemplate(template: string, values: Record<string, string>): string {
  const url = template.replace(/\{(\w+)\}/g, (_m, name: string) => {
    const value = values[name];
    if (value === undefined) throw new PatternError(`URL template has no value for {${name}}`, 'runtime');
    const segments = value.split('/');
    for (const s of segments) {
      if (s === '.' || s === '..' || s.includes('\\') || s.includes('\0'))
        throw new PatternError('refusing a path segment that climbs', 'format');
    }
    return segments.map(encodeURIComponent).join('/');
  });
  let ok = false;
  try {
    ok = new URL(url).origin === new URL(template.replace(/\{\w+\}/g, 'x')).origin;
  } catch {
    ok = false;
  }
  if (!ok) throw new PatternError('URL left its origin', 'format');
  return url;
}

/** Globs: `*` inside a segment, `**` across segments. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

export function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i] as string;
    if (quoted) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else quoted = false;
      } else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out;
}

/** RFC 4180 rows (quoted fields may hold newlines). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cur = '';
  let quoted = false;
  const endRow = () => {
    row.push(cur);
    cur = '';
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cur += '"';
          i++;
        } else quoted = false;
      } else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(cur);
      cur = '';
    } else if (c === '\n') endRow();
    else if (c !== '\r') cur += c;
  }
  if (cur !== '' || row.length) endRow();
  return rows;
}

export function rejectXmlEntities(text: string): void {
  if (/<!ENTITY/i.test(text)) throw new PatternError('XML declares entities', 'format');
}

/** Runs `fn` for each entry in parallel. Returns results up to the first `too-large`, and that entry. */
export async function mapUntilTooLarge<T, R>(
  entries: readonly T[],
  fn: (entry: T) => Promise<R>,
): Promise<{ done: R[]; big: number | null }> {
  const settled = await Promise.all(
    entries.map((e) =>
      fn(e).then(
        (value) => ({ ok: true as const, value }),
        (err: unknown) => {
          if (err instanceof PatternError && err.code === 'too-large') return { ok: false as const };
          throw err;
        },
      ),
    ),
  );
  const done: R[] = [];
  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    if (!s?.ok) return { done, big: i };
    done.push(s.value);
  }
  return { done, big: null };
}

/**
 * Newest-first walk shared by `feed` and `page`: entries after the cursor's key, the oldest `take` of them
 * (oldest first), whether more remain, and whether the cursor's key was lost.
 */
export function pickNew<T extends { key: string }>(
  entries: readonly T[],
  order: 'newest-first' | 'oldest-first',
  cursorKey: string | null,
  take: number,
): { fresh: T[]; more: boolean; gap: boolean; newestKey: string | null } {
  const newestFirst = order === 'newest-first' ? [...entries] : [...entries].reverse();
  const newestKey = newestFirst[0]?.key ?? null;
  let gap = false;
  let candidates = newestFirst;
  if (cursorKey !== null) {
    const at = newestFirst.findIndex((e) => e.key === cursorKey);
    if (at >= 0) candidates = newestFirst.slice(0, at);
    else gap = true;
  }
  const oldestFirst = [...candidates].reverse();
  return { fresh: oldestFirst.slice(0, take), more: oldestFirst.length > take, gap, newestKey };
}

/**
 * An item link is kept only as an absolute `http:` or `https:` URL (later pages render it).
 * `base` resolves relative values; without it the value must already be absolute.
 */
export function httpUrl(value: string, base?: string): string | null {
  try {
    const u = base ? new URL(value.trim(), base) : new URL(value.trim());
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}
