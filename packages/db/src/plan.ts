import { type InboxRow, MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import type { DatabaseName } from './databases';
import { jsonDeleteSql, jsonUpsertSql, MAX_STATEMENTS_PER_INVOCATION } from './sql';
import { type ColumnInfo, TABLES, type TableInfo, WRITE_ORDER } from './table-info';

/** Half of D1's 2,000,000-byte string limit (checked 23 Nov 2026, d1/platform/limits). */
export const MAX_PARAM_BYTES = 1_000_000;

/** A row that can't be written. The message names the row's index, table and column, never a value. */
export class RowValidationError extends Error {
  readonly index: number;
  readonly table: string | undefined;
  constructor(index: number, table: string | undefined, reason: string, column?: string) {
    super(`row ${index}${table === undefined ? '' : ` (${table}${column ? `.${column}` : ''})`}: ${reason}`);
    this.name = 'RowValidationError';
    this.index = index;
    this.table = table;
  }
}

/** A call too big for one invocation. */
export class WriteLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WriteLimitError';
  }
}

export interface PlannedStatement {
  db: DatabaseName;
  table: string;
  op: 'upsert' | 'delete';
  sql: string;
  params: [string];
  rows: number;
}

export interface WritePlan {
  statements: PlannedStatement[];
  rows: number;
  cost: number;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/** Checks one value for its column and returns what goes into the JSON parameter. */
function cell(index: number, table: string, name: string, col: ColumnInfo, v: unknown): unknown {
  const bad = (why: string) => new RowValidationError(index, table, why, name);
  if (v === null) {
    if (col.notNull) throw bad('null in a NOT NULL column');
    return null;
  }
  switch (typeof v) {
    case 'string':
      // SQLite's column affinity would quietly coerce a string into a number column; refuse it instead.
      if (col.type !== 'text') throw bad('string in a number column');
      return v;
    case 'number':
      if (!Number.isFinite(v)) throw bad('number is not finite');
      if (col.type === 'text') throw bad('number in a text column');
      if (col.type === 'integer' && !Number.isSafeInteger(v)) throw bad('not a safe integer');
      return v;
    case 'boolean':
      if (col.type !== 'integer') throw bad('boolean outside an integer column');
      return v ? 1 : 0;
    case 'object':
      if (col.type !== 'text') throw bad('array or object outside a text column');
      if (Array.isArray(v) || isPlainObject(v)) return JSON.stringify(v);
      throw bad('unsupported object');
    default:
      throw bad(`unsupported ${typeof v}`);
  }
}

interface Checked {
  index: number;
  info: TableInfo;
  op: 'upsert' | 'delete';
  values: Record<string, unknown>;
  cols: string[];
}

function checkRow(index: number, r: InboxRow): Checked {
  const raw = r as unknown;
  if (!isPlainObject(raw)) throw new RowValidationError(index, undefined, 'row is not an object');
  const table = raw.table;
  const info = typeof table === 'string' ? TABLES.get(table) : undefined;
  if (!info || typeof table !== 'string')
    throw new RowValidationError(index, typeof table === 'string' ? table : undefined, 'unknown table');
  if (info.rule === 'none') throw new RowValidationError(index, table, 'table cannot be written');
  const op = raw.op;
  if (op !== 'upsert' && op !== 'delete')
    throw new RowValidationError(index, table, 'op must be upsert or delete');
  const row = raw.row;
  if (!isPlainObject(row)) throw new RowValidationError(index, table, 'row must be a plain object');
  const cols = Object.keys(row);
  for (const c of cols) {
    if (!info.columns.has(c)) throw new RowValidationError(index, table, 'unknown column', c);
  }
  for (const k of info.primaryKey) {
    if (row[k] === undefined || row[k] === null)
      throw new RowValidationError(index, table, 'primary key column missing or null', k);
  }
  if (op === 'upsert') {
    for (const [name, c] of info.columns) {
      if (c.notNull && !c.hasDefault && row[name] === undefined)
        throw new RowValidationError(index, table, 'NOT NULL column missing', name);
    }
  } else {
    for (const c of cols) {
      if (!info.primaryKey.includes(c))
        throw new RowValidationError(index, table, 'a delete carries only key columns', c);
    }
  }
  const values: Record<string, unknown> = {};
  for (const c of cols) {
    const col = info.columns.get(c) as ColumnInfo;
    values[c] = cell(index, table, c, col, row[c]);
  }
  return { index, info, op, values, cols: [...cols].sort() };
}

const encoder = new TextEncoder();

/**
 * Validates `rows` and plans the D1 statements that write them. Pure: no I/O. Any failure throws before
 * anything is written. Each statement binds one JSON array of rows, so the 100-parameter limit never applies.
 */
export function planWrites(rows: readonly InboxRow[]): WritePlan {
  if (rows.length > MAX_ROWS_PER_CHUNK)
    throw new WriteLimitError(`${rows.length} rows is over the limit of ${MAX_ROWS_PER_CHUNK} per call`);

  // Validate every row, and keep the last row for each primary key.
  const last = new Map<string, Checked>();
  rows.forEach((r, i) => {
    const c = checkRow(i, r);
    const key = JSON.stringify([c.info.name, ...c.info.primaryKey.map((k) => c.values[k])]);
    last.delete(key); // re-insert so Map order follows the last occurrence
    last.set(key, c);
  });

  // Group by table, op, then exact column set.
  const groups = new Map<string, { c: Checked; rows: Checked[] }>();
  for (const c of last.values()) {
    const g = `${c.info.name}\0${c.op}\0${c.cols.join(',')}`;
    const existing = groups.get(g);
    if (existing) existing.rows.push(c);
    else groups.set(g, { c, rows: [c] });
  }
  const order = (name: string) => WRITE_ORDER.indexOf(name);
  const sorted = [...groups.entries()].sort(([ak, a], [bk, b]) => {
    const t = order(a.c.info.name) - order(b.c.info.name);
    if (t !== 0) return t;
    const o = (a.c.op === 'upsert' ? 0 : 1) - (b.c.op === 'upsert' ? 0 : 1);
    return o !== 0 ? o : ak < bk ? -1 : ak > bk ? 1 : 0;
  });

  const statements: PlannedStatement[] = [];
  let cost = 0;
  for (const [, { c, rows: grouped }] of sorted) {
    const { info, op } = c;
    const sql = op === 'upsert' ? jsonUpsertSql(info, c.cols) : jsonDeleteSql(info);
    let chunk: string[] = [];
    let bytes = 2;
    const flush = () => {
      if (chunk.length === 0) return;
      statements.push({
        db: info.db,
        table: info.name,
        op,
        sql,
        params: [`[${chunk.join(',')}]`],
        rows: chunk.length,
      });
      chunk = [];
      bytes = 2;
    };
    for (const item of grouped) {
      const json = JSON.stringify(item.values);
      const size = encoder.encode(json).length;
      if (size + 2 > MAX_PARAM_BYTES)
        throw new RowValidationError(item.index, info.name, 'row is over the size limit');
      if (bytes + size + 1 > MAX_PARAM_BYTES) flush();
      chunk.push(json);
      bytes += size + 1;
    }
    flush();
    cost += grouped.length * (1 + info.secondaryIndexes);
  }
  if (statements.length > MAX_STATEMENTS_PER_INVOCATION)
    throw new WriteLimitError(
      `${statements.length} statements is over the limit of ${MAX_STATEMENTS_PER_INVOCATION} per call`,
    );
  return { statements, rows: last.size, cost };
}
