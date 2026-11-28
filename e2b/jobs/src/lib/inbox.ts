import { gzipSync } from 'node:zlib';
import {
  type InboxManifest,
  type InboxRow,
  inboxChunkKey,
  inboxManifestKey,
  MAX_ROWS_PER_CHUNK,
} from '@ti/core/inbox';
import type { JobApi } from '../client.ts';
import { mapLimited } from './pool.ts';

const UPLOADS_IN_FLIGHT = 4;

/**
 * Writes chunks that are already packed (1 to 500 rows each) as gzipped NDJSON, then the manifest last (ti-api
 * reads the manifest on `complete`). With no chunks it still writes an empty manifest.
 */
export async function writeInboxChunks(
  api: JobApi,
  jobId: string,
  chunks: InboxRow[][],
  now: () => Date = () => new Date(),
  cursor?: InboxManifest['cursor'],
): Promise<{ chunks: number }> {
  const slices = chunks.map((rows, n) => {
    if (rows.length === 0 || rows.length > MAX_ROWS_PER_CHUNK)
      throw new Error(`chunk ${n} has ${rows.length} rows`);
    return { key: inboxChunkKey(jobId, n), rows };
  });
  // Chunks upload a few at a time; the manifest waits until every one has succeeded.
  await mapLimited(slices, UPLOADS_IN_FLIGHT, async (s) => {
    const body = gzipSync(`${s.rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
    await api.putObject(s.key, body, 'application/gzip');
  });
  const manifest = slices.map((s) => ({ key: s.key, rows: s.rows.length }));
  await api.putObject(
    inboxManifestKey(jobId),
    JSON.stringify({
      jobId,
      createdAt: now().toISOString(),
      chunks: manifest,
      ...(cursor ? { cursor } : {}),
    }),
    'application/json',
  );
  return { chunks: manifest.length };
}

/** Writes `rows` as chunks of at most 500 rows, then the manifest last. With no rows: an empty manifest. */
export function writeInbox(
  api: JobApi,
  jobId: string,
  rows: InboxRow[],
  now: () => Date = () => new Date(),
  cursor?: InboxManifest['cursor'],
): Promise<{ chunks: number }> {
  const chunks: InboxRow[][] = [];
  for (let i = 0; i < rows.length; i += MAX_ROWS_PER_CHUNK)
    chunks.push(rows.slice(i, i + MAX_ROWS_PER_CHUNK));
  return writeInboxChunks(api, jobId, chunks, now, cursor);
}
