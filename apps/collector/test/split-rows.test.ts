import type { InboxRow } from '@ti/core/inbox';
import { expect, it } from 'vitest';
import { splitRows } from '../src/step';

const row = (table: string): InboxRow => ({ table, op: 'upsert', row: {} });

it("splits at 500 rows and keeps a record's package rows together where it can", () => {
  const rows = [
    ...Array.from({ length: 497 }, () => row('vulns')),
    row('affected'),
    row('affected'),
    row('affected'),
    row('package_advisories'),
  ];
  const parts = splitRows(rows);
  expect(parts.map((p) => p.length)).toEqual([497, 4]);
  expect(parts.flat()).toEqual(rows);
});

it('small writes stay in one call; a long run with no boundary is cut at 500', () => {
  expect(splitRows([row('vulns')])).toHaveLength(1);
  const parts = splitRows(Array.from({ length: 1200 }, () => row('affected')));
  expect(parts.map((p) => p.length)).toEqual([500, 500, 200]);
});
