import { normaliseId } from '@ti/core/ids';
import { lookupVulnKey } from '@ti/core/r2-keys';
import { databaseFor } from '@ti/db/tables';
import { databasesFromEnv } from '@ti/db/write';
import type { LinkDeps } from '@ti/linker/link';
import type { Env } from './env';
import { PermanentError } from './errors';

/** D1 allows 100 bound parameters per statement. */
const MAX_PARAMS = 100;
const IDENT = /^[a-z_]+$/;
const FORBIDDEN_DBS = new Set(['ti_users', 'ti_control']);

type LinkEnv = Pick<Env, 'DB_CONTROL' | 'DB_VULNS' | 'DB_ADVISORIES' | 'DB_SIGNALS' | 'DB_WORLD' | 'BUCKET'>;

/** The linker's read access: keyed row lookups in the data databases, and the cold-vulnerability file. */
export function linkDeps(env: LinkEnv, deps: Pick<LinkDeps, 'now' | 'newId'>): LinkDeps {
  return {
    now: deps.now,
    newId: deps.newId,
    read: (table, keys) => readRows(env, table, keys),
    lookupCold: (key) => lookupCold(env.BUCKET, key),
  };
}

async function readRows(
  env: LinkEnv,
  table: string,
  keys: Record<string, unknown>[],
): Promise<Record<string, unknown>[]> {
  if (keys.length === 0) return [];
  if (!IDENT.test(table)) throw new PermanentError('link read: bad table name');
  const dbName = databaseFor(table); // throws for an unknown table
  if (FORBIDDEN_DBS.has(dbName)) throw new PermanentError(`link read: ${dbName} is not readable`);
  const db = databasesFromEnv(env as unknown as Record<string, unknown>)[dbName];
  if (!db) throw new PermanentError(`link read: no binding for ${dbName}`);

  const first = keys[0] as Record<string, unknown>;
  const cols = Object.keys(first);
  if (cols.length === 0 || cols.length > MAX_PARAMS) throw new PermanentError('link read: bad key shape');
  for (const c of cols) if (!IDENT.test(c)) throw new PermanentError('link read: bad column name');
  for (const k of keys) {
    const kc = Object.keys(k);
    if (kc.length !== cols.length || !cols.every((c) => Object.hasOwn(k, c))) {
      throw new PermanentError('link read: keys have different columns');
    }
  }

  const perStatement = Math.floor(MAX_PARAMS / cols.length);
  const tuple = `(${cols.map(() => '?').join(',')})`;
  const statements: D1PreparedStatement[] = [];
  for (let i = 0; i < keys.length; i += perStatement) {
    const chunk = keys.slice(i, i + perStatement);
    const sql = `SELECT * FROM ${table} WHERE (${cols.join(',')}) IN (VALUES ${chunk.map(() => tuple).join(',')})`;
    const params = chunk.flatMap((k) => cols.map((c) => k[c] ?? null));
    statements.push(db.prepare(sql).bind(...params));
  }
  const results = await db.batch<Record<string, unknown>>(statements);
  return results.flatMap((r) => r.results);
}

async function lookupCold(bucket: R2Bucket, vulnKey: string): Promise<Record<string, unknown> | null> {
  const obj = await bucket.get(lookupVulnKey(vulnKey));
  if (!obj) return null;
  const shard = (await obj.json()) as unknown;
  if (typeof shard !== 'object' || shard === null || Array.isArray(shard)) return null;
  const key = normaliseId(vulnKey);
  if (!Object.hasOwn(shard, key)) return null;
  const row = (shard as Record<string, unknown>)[key];
  return typeof row === 'object' && row !== null && !Array.isArray(row)
    ? (row as Record<string, unknown>)
    : null;
}
