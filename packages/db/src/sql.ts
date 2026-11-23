import type { TableInfo } from './table-info';

/**
 * Max statements we send per invocation. Kept at 40 to bound batch size and CPU time per step (the
 * account is on Workers Paid, so this is not a plan limit).
 */
export const MAX_STATEMENTS_PER_INVOCATION = 40;

/**
 * "Newer wins" upsert: re-running a batch is harmless, and an older copy never overwrites a newer one.
 * `cols` must include `modified`. D1 allows 100 bound parameters per statement (checked 23 Nov 2026, d1/platform/limits), so
 * big groups of rows use `jsonUpsertSql`, which binds one JSON parameter instead.
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

const jsonField = (c: string) => `json_extract(value, '$.${c}')`;

/**
 * Upsert a group of rows bound as one JSON array (`?1`), so a statement never nears D1's 100-parameter limit.
 * Every name comes from `TableInfo` and `cols` (already checked against it), never from row data.
 * `WHERE true` is required when an upsert takes its rows from a SELECT, or SQLite reads ON as a join.
 */
export function jsonUpsertSql(t: TableInfo, cols: readonly string[]): string {
  let conflict: string;
  if (t.rule === 'insert-ignore') {
    conflict = 'DO NOTHING';
  } else {
    const never = t.rule === 'keep-first-seen' ? 'first_seen' : undefined;
    const updates = cols
      .filter((c) => !t.primaryKey.includes(c) && c !== never)
      .map((c) => `${c} = excluded.${c}`);
    if (updates.length === 0) {
      conflict = 'DO NOTHING';
    } else {
      const guard =
        t.rule === 'newer' && t.versionColumn
          ? ` WHERE excluded.${t.versionColumn} > ${t.name}.${t.versionColumn}`
          : '';
      conflict = `DO UPDATE SET ${updates.join(', ')}${guard}`;
    }
  }
  return (
    `INSERT INTO ${t.name} (${cols.join(', ')}) SELECT ${cols.map(jsonField).join(', ')} ` +
    `FROM json_each(?1) WHERE true ON CONFLICT (${t.primaryKey.join(', ')}) ${conflict}`
  );
}

/** Delete a group of rows by primary key, the keys bound as one JSON array (`?1`). */
export function jsonDeleteSql(t: TableInfo): string {
  return (
    `DELETE FROM ${t.name} WHERE (${t.primaryKey.join(', ')}) IN ` +
    `(SELECT ${t.primaryKey.map(jsonField).join(', ')} FROM json_each(?1))`
  );
}
