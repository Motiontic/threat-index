import { rawReceiptKey } from '@ti/core/r2-keys';
import type { RawItem } from '@ti/patterns/types';
import { decodeTime } from 'ulid';

export interface ReceiptInput {
  sourceId: string;
  runId: string;
  step: number;
  now: Date;
  receipt: { fetchedAt: string; contentType: string; body: ArrayBuffer | string } | null;
  items: readonly RawItem[];
  /** A `link` display-mode source keeps ids and metadata only, never bodies. */
  linkOnly: boolean;
}

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** The NDJSON text of a receipt: one `receipt` line, then one `item` line per item. */
export function receiptText(input: ReceiptInput): string {
  const { receipt } = input;
  const head: Record<string, unknown> = {
    type: 'receipt',
    source: input.sourceId,
    runId: input.runId,
    step: input.step,
    fetchedAt: receipt?.fetchedAt ?? input.now.toISOString(),
    contentType: receipt?.contentType ?? 'application/json',
  };
  if (receipt && !input.linkOnly) {
    const binary = typeof receipt.body !== 'string';
    head.encoding = binary ? 'base64' : 'utf8';
    head.body = binary ? toBase64(receipt.body as ArrayBuffer) : receipt.body;
  }
  const lines = [JSON.stringify(head)];
  for (const item of input.items) {
    lines.push(
      JSON.stringify(
        input.linkOnly ? { type: 'item', id: item.id } : { type: 'item', id: item.id, body: item.body },
      ),
    );
  }
  return `${lines.join('\n')}\n`;
}

async function gzip(text: string): Promise<ArrayBuffer> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Response(stream).arrayBuffer();
}

/**
 * Writes the receipt to R2 under raw/<source>/<day of the run>/<runId>-<step>.ndjson.gz. A redelivered step
 * writes the same key. Returns the uncompressed length.
 */
export async function writeReceipt(bucket: R2Bucket, input: ReceiptInput): Promise<number> {
  const text = receiptText(input);
  const key = rawReceiptKey(input.sourceId, input.runId, input.step, new Date(decodeTime(input.runId)));
  await bucket.put(key, await gzip(text), { httpMetadata: { contentType: 'application/gzip' } });
  return new TextEncoder().encode(text).length;
}
