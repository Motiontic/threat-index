/**
 * D1 helpers. Tables use natural primary keys (WITHOUT ROWID) so one row costs one write.
 * Migrations live in ../migrations/<database>/ and are applied with `pnpm --filter @ti/db migrate:local`.
 */
export const DATABASES = [
  'ti_control',
  'ti_vulns',
  'ti_advisories',
  'ti_signals',
  'ti_world',
  'ti_users',
] as const;
export type DatabaseName = (typeof DATABASES)[number];

/** Max statements we send per invocation (free plan allows 50 queries per Worker invocation). */
export const MAX_STATEMENTS_PER_INVOCATION = 40;

/**
 * "Newer wins" upsert: re-running a batch is harmless, and an older copy never overwrites a newer one.
 * `cols` must include `modified`. Bound-parameter limits apply per statement (verify current D1 limit).
 */
export function upsertNewerSql(
  table: string,
  cols: readonly string[],
  keyCols: readonly string[],
  rows: number,
): string {
  const placeholders = Array.from(
    { length: rows },
    (_, r) => `(${cols.map((_, c) => `?${r * cols.length + c + 1}`).join(', ')})`,
  ).join(', ');
  const updates = cols
    .filter((c) => !keyCols.includes(c))
    .map((c) => `${c} = excluded.${c}`)
    .join(', ');
  return (
    `INSERT INTO ${table} (${cols.join(', ')}) VALUES ${placeholders} ` +
    `ON CONFLICT (${keyCols.join(', ')}) DO UPDATE SET ${updates} WHERE excluded.modified > ${table}.modified`
  );
}
