import { gzipSync } from 'node:zlib';
import { type InboxRow, inboxChunkKey, inboxManifestKey, MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import type { JobApi } from '../client.ts';
import { mapLimited } from './pool.ts';

const UPLOADS_IN_FLIGHT = 4;

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
  const slices: { key: string; rows: InboxRow[] }[] = [];
  for (let i = 0; i < rows.length; i += MAX_ROWS_PER_CHUNK)
    slices.push({ key: inboxChunkKey(jobId, slices.length), rows: rows.slice(i, i + MAX_ROWS_PER_CHUNK) });
  // Chunks upload a few at a time; the manifest waits until every one has succeeded.
  await mapLimited(slices, UPLOADS_IN_FLIGHT, async (s) => {
    const body = gzipSync(`${s.rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
    await api.putObject(s.key, body, 'application/gzip');
  });
  const chunks = slices.map((s) => ({ key: s.key, rows: s.rows.length }));
  await api.putObject(
    inboxManifestKey(jobId),
    JSON.stringify({ jobId, createdAt: now().toISOString(), chunks }),
    'application/json',
  );
  return { chunks: chunks.length };
}
