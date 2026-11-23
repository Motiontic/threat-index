import { gzipSync } from 'node:zlib';
import { type InboxRow, inboxChunkKey, inboxManifestKey, MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import type { JobApi } from '../client.ts';

/**
 * Writes `rows` as gzipped NDJSON chunks, then the manifest last (ti-api reads the manifest on `complete`).
 * With no rows it still writes an empty manifest.
 */
export async function writeInbox(
  api: JobApi,
  jobId: string,
  rows: InboxRow[],
  now: () => Date = () => new Date(),
): Promise<{ chunks: number }> {
  const chunks: { key: string; rows: number }[] = [];
  for (let i = 0; i < rows.length; i += MAX_ROWS_PER_CHUNK) {
    const slice = rows.slice(i, i + MAX_ROWS_PER_CHUNK);
    const key = inboxChunkKey(jobId, chunks.length);
    const body = gzipSync(`${slice.map((r) => JSON.stringify(r)).join('\n')}\n`);
    await api.putObject(key, body, 'application/gzip');
    chunks.push({ key, rows: slice.length });
  }
  await api.putObject(
    inboxManifestKey(jobId),
    JSON.stringify({ jobId, createdAt: now().toISOString(), chunks }),
    'application/json',
  );
  return { chunks: chunks.length };
}
