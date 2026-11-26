import { gzipSync } from 'node:zlib';
import type { InboxRow } from '@ti/core/inbox';
import { planWrites } from '@ti/db/plan';
import { expect, it } from 'vitest';
import { AFFECTED_KEY, ROW_COST } from '../../../packages/linker/src/affected';
import { readChunk } from './chunk';
import { INBOX_TABLES } from './inbox-tables';

const affected = (n: number): Record<string, unknown> => ({
  ecosystem: 'npm',
  name: 'a',
  source: 'github-advisory-db',
  source_id: 'GHSA-aaaa-bbbb-cccc',
  range_no: n,
  vuln_key: 'CVE-2026-1',
  range_type: 'ECOSYSTEM',
  introduced: '0',
  fixed: '1.0.0',
  last_affected: null,
  versions: null,
});
const advisory = {
  source: 'github-advisory-db',
  source_id: 'GHSA-aaaa-bbbb-cccc',
  vuln_key: 'CVE-2026-1',
  status: 'active',
  summary: 's',
  severity: null,
  reviewed: 1,
  url: null,
  published: null,
  modified: '2026-01-01T00:00:00.000Z',
};
const rows: InboxRow[] = [
  { table: 'affected', op: 'upsert', row: affected(0) },
  { table: 'affected', op: 'upsert', row: affected(1) },
  {
    table: 'affected',
    op: 'delete',
    row: Object.fromEntries(AFFECTED_KEY.map((c) => [c, affected(2)[c]])),
  },
  { table: 'package_advisories', op: 'upsert', row: advisory },
];

it('the loader allows both package tables', () => {
  expect(INBOX_TABLES.has('affected')).toBe(true);
  expect(INBOX_TABLES.has('package_advisories')).toBe(true);
});

it('a package chunk passes readChunk and planWrites, at 3 and 2 units per row', async () => {
  const body = gzipSync(rows.map((r) => JSON.stringify(r)).join('\n'));
  const read = await readChunk(
    { size: body.length, body: new Response(body).body as ReadableStream<Uint8Array> },
    rows.length,
  );
  expect(read).toEqual(rows);
  const plan = planWrites(read);
  expect(plan.rows).toBe(4);
  expect(plan.cost).toBe(3 * ROW_COST.affected + ROW_COST.package_advisories);
  expect(plan.cost).toBe(11);
});
