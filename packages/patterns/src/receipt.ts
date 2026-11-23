import type { Receipt } from '@ti/core/types';
import type { PatternContext } from './types';

export interface ReceiptPart {
  url: string;
  status: number;
  contentType: string;
  body: string;
}

/** One `application/x-ndjson` line per response the items came from. `null` when there is nothing. */
export function buildReceipt(ctx: PatternContext, parts: readonly ReceiptPart[]): Receipt | null {
  if (parts.length === 0) return null;
  return {
    source: ctx.source.id,
    runId: ctx.runId ?? '',
    fetchedAt: ctx.now().toISOString(),
    contentType: 'application/x-ndjson',
    body: `${parts
      .map((p) => JSON.stringify({ url: p.url, status: p.status, contentType: p.contentType, body: p.body }))
      .join('\n')}\n`,
  };
}
