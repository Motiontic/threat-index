import { expect, it } from 'vitest';
import { inboxChunkKey, inboxManifestKey, MAX_ROWS_PER_CHUNK } from './inbox';

it('builds inbox keys', () => {
  expect(inboxChunkKey('job1', 3)).toBe('inbox/job1/3.ndjson.gz');
  expect(inboxManifestKey('job1')).toBe('inbox/job1/manifest.json');
  expect(MAX_ROWS_PER_CHUNK).toBe(500);
});
