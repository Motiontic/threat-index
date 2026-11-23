import type { InboxRow } from '@ti/core/inbox';
import { INBOX_TABLES } from './inbox-tables';

export const MAX_STORED_BYTES = 4 * 1024 * 1024;
export const MAX_UNZIPPED_BYTES = 16 * 1024 * 1024;

/** The chunk can never load: retrying won't help. The reason never contains row contents. */
export class CorruptChunkError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'CorruptChunkError';
  }
}

/** The R2 body stream failed (not the data in it). Retryable, unlike CorruptChunkError. */
export class ChunkReadError extends Error {
  constructor(cause: unknown) {
    super(`R2 body read failed: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    this.name = 'ChunkReadError';
  }
}

async function gunzip(body: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  // Wrap the source so an error from R2 itself can be told apart from a gzip format error.
  const source = body.getReader();
  let sourceError: { error: unknown } | undefined;
  const tagged = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const r = await source.read();
        if (r.done) controller.close();
        else controller.enqueue(r.value);
      } catch (error) {
        sourceError = { error };
        controller.error(error);
      }
    },
    cancel: (reason) => source.cancel(reason),
  });
  const reader = tagged.pipeThrough(new DecompressionStream('gzip')).getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_UNZIPPED_BYTES) {
        await reader.cancel();
        throw new CorruptChunkError(`over ${MAX_UNZIPPED_BYTES} bytes unzipped`);
      }
      parts.push(value);
    }
  } catch (err) {
    if (err instanceof CorruptChunkError) throw err;
    if (sourceError) throw new ChunkReadError(sourceError.error);
    throw new CorruptChunkError('not valid gzip');
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.byteLength;
  }
  return all;
}

/** Reads one gzipped NDJSON chunk of `{ table, op, row }` lines. Throws CorruptChunkError if it is bad. */
export async function readChunk(
  object: { size: number; body: ReadableStream<Uint8Array> },
  expectedRows: number,
): Promise<InboxRow[]> {
  if (object.size > MAX_STORED_BYTES) throw new CorruptChunkError(`over ${MAX_STORED_BYTES} bytes stored`);
  const bytes = await gunzip(object.body);
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  const rows: InboxRow[] = [];
  let start = 0;
  let line = 0;
  while (start < bytes.length) {
    let end = bytes.indexOf(10, start);
    if (end === -1) end = bytes.length;
    line++;
    let text: string;
    try {
      text = decoder.decode(bytes.subarray(start, end));
    } catch {
      throw new CorruptChunkError(`line ${line}: not valid UTF-8`);
    }
    start = end + 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new CorruptChunkError(`line ${line}: not JSON`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
      throw new CorruptChunkError(`line ${line}: not an object`);
    const { table, op, row } = parsed as Record<string, unknown>;
    if (
      typeof table !== 'string' ||
      typeof op !== 'string' ||
      typeof row !== 'object' ||
      row === null ||
      Array.isArray(row)
    )
      throw new CorruptChunkError(`line ${line}: not { table, op, row }`);
    if (!INBOX_TABLES.has(table)) throw new CorruptChunkError(`line ${line}: table not allowed in the inbox`);
    rows.push({ table, op: op as InboxRow['op'], row: row as Record<string, unknown> });
    if (rows.length > expectedRows)
      throw new CorruptChunkError(`line ${line}: more than ${expectedRows} lines`);
  }
  if (rows.length !== expectedRows)
    throw new CorruptChunkError(`${rows.length} lines, but the message says ${expectedRows}`);
  return rows;
}
