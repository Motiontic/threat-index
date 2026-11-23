import type { JobRequest } from '@ti/core/control';
import type { CredentialName, Cursor, Receipt } from '@ti/core/types';
import type { PatternName, SourceConfig } from '@ti/sources/registry';

/**
 * Every source fits one of seven pull patterns. Each one first asks cheaply whether
 * anything changed, then fetches only the new part. Max 40 items per call (10 ms CPU, 50 subrequests).
 *
 * A parser's input is one `RawItem.body`. A pattern that fetches a whole document returns, per item, that
 * document with its records array cut to the one entry, so a whole-document parser such as `kev` works
 * unchanged.
 */
export const MAX_ITEMS_PER_STEP = 40;

export interface PatternContext {
  source: SourceConfig;
  cursor: Cursor | null;
  userAgent: string;
  fetch: typeof fetch;
  signal?: AbortSignal;
  /** Waits without using CPU. In Workers this is `scheduler.wait`. */
  wait(ms: number): Promise<void>;
  log(msg: string, extra?: Record<string, unknown>): void;
  now(): Date;
  /** Copied into the receipt. */
  runId?: string;
  /**
   * Credentials the collector passes from its optional secrets, and nothing else from its environment.
   * A pattern sends a credential only to the origin it belongs to.
   */
  credentials?: Readonly<Partial<Record<CredentialName, string>>>;
}

export interface RawItem {
  id: string;
  body: unknown;
}

/** The collector adds `requestId` and the pattern's `nextCursor` when it sends the request. */
export type HeavyJobRequest = Omit<JobRequest, 'requestId' | 'cursor'>;

export interface PatternResult {
  items: RawItem[];
  receipt: Receipt | null;
  /**
   * Committed only after the records are safely written. `null` means there is nothing to commit: the run
   * found nothing and there was no cursor to keep (a first run on an empty source). The caller leaves the
   * stored cursor as it is and must never write an empty value.
   */
  nextCursor: Cursor | null;
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
