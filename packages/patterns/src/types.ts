import type { Cursor, Receipt } from '@ti/core/types';
import type { PatternName, SourceConfig } from '@ti/sources/registry';

/**
 * Every source fits one of seven pull patterns. Each one first asks cheaply whether
 * anything changed, then fetches only the new part. Max 40 items per call (10 ms CPU, 50 subrequests).
 */
export const MAX_ITEMS_PER_STEP = 40;

export interface PatternContext {
  source: SourceConfig;
  cursor: Cursor | null;
  userAgent: string;
  fetch: typeof fetch;
  signal?: AbortSignal;
}

export interface RawItem {
  id: string;
  body: unknown;
}

export interface HeavyJobRequest {
  kind: 'big-file' | 'first-load' | 'epss-diff';
  sourceId: string;
  url?: string;
  reason: string;
}

export interface PatternResult {
  items: RawItem[];
  receipt: Receipt | null;
  /** Committed only after the records are safely written. */
  nextCursor: Cursor;
  /** More pages remain: enqueue a continuation message. */
  more: boolean;
  /** Too big for a Worker: hand off to E2B. */
  heavy?: HeavyJobRequest;
}

export interface Pattern {
  readonly name: PatternName;
  check(ctx: PatternContext): Promise<'unchanged' | 'changed'>;
  fetch(ctx: PatternContext): Promise<PatternResult>;
}

/** Conditional GET helper shared by fingerprint/changelist patterns. */
export async function conditionalGet(
  ctx: PatternContext,
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('user-agent', ctx.userAgent);
  if (ctx.cursor?.etag) headers.set('if-none-match', ctx.cursor.etag);
  return ctx.fetch(url, { ...init, headers, signal: ctx.signal });
}
