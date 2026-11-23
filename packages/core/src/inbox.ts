import type { WritePriority } from './budget';

export const MAX_ROWS_PER_CHUNK = 500;

/**
 * One D1 row on its way in. `table` is a table name from packages/db/migrations, and the keys of `row`
 * are that table's SQL column names (`source_id`, not `sourceId`).
 */
export interface InboxRow {
  table: string;
  op: 'upsert' | 'delete';
  row: Record<string, unknown>;
}

/** Written by a sandbox. Carries no priority: ti-api sets that from the job kind. */
export interface InboxChunkRef {
  key: string; // inbox/<jobId>/<n>.ndjson.gz
  rows: number;
}

export interface InboxManifest {
  jobId: string;
  createdAt: string; // ISO
  chunks: InboxChunkRef[];
}

/**
 * One ti-load message: one inbox chunk. ti-api sets `priority` from the job's kind (`first-load` jobs →
 * 'first-load', every other kind → 'steady'), never from anything the sandbox wrote, so a sandbox can't
 * skip the first-load cap.
 */
export interface LoadMessage {
  jobId: string;
  chunkKey: string;
  rows: number;
  priority: WritePriority;
}

/** inbox/<jobId>/<n>.ndjson.gz */
export function inboxChunkKey(jobId: string, n: number): string {
  return `inbox/${jobId}/${n}.ndjson.gz`;
}

/** inbox/<jobId>/manifest.json */
export function inboxManifestKey(jobId: string): string {
  return `inbox/${jobId}/manifest.json`;
}
