import { execFile as nodeExecFile } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { lakeKey } from '@ti/core/r2-keys';
import { MAX_OBJECT_BYTES } from '../client.ts';

export type LakeFormat = 'parquet' | 'ndjson.gz';
export type LakeColumns = Record<string, 'VARCHAR' | 'DOUBLE' | 'BIGINT'>;
export type ExecFile = (
  file: string,
  args: string[],
  opts: { env: Record<string, string>; maxBuffer: number; timeout: number },
) => Promise<unknown>;

export interface LakeDeps {
  /** Used in temp directory names, never data. */
  jobId: string;
  execFile?: ExecFile;
  /** Absolute path of the DuckDB CLI, or null when it is not installed. */
  duckdb?: () => string | null;
  log?: (msg: string, extra?: Record<string, unknown>) => void;
}

const SAFE_ID = /^[A-Za-z0-9-]{1,64}$/;
const SAFE_COLUMN = /^[a-z_][a-z0-9_]*$/;
const DUCKDB_TIMEOUT_MS = 10 * 60 * 1000;

const defaultExecFile: ExecFile = (file, args, opts) =>
  new Promise((resolve, reject) => {
    nodeExecFile(file, args, opts, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });

/** Finds `duckdb` on PATH. The child gets an empty environment, so the caller needs an absolute path. */
export function findDuckdb(path: string = process.env.PATH ?? ''): string | null {
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, 'duckdb');
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* not here */
    }
  }
  return null;
}

/** lake/<table>/<source>/<year>/part-<part>.parquet, or the same key ending `.ndjson.gz`. */
export function lakeObjectKey(
  table: string,
  sourceId: string,
  year: number,
  part: string | number,
  format: LakeFormat,
): string {
  // `lakeKey` only interpolates `part`; the jobs name a part by job id or by day.
  const key = lakeKey(table, sourceId, year, part as number);
  return format === 'parquet' ? key : key.replace(/\.parquet$/, '.ndjson.gz');
}

const ndjson = (rows: readonly unknown[]): string =>
  rows.length === 0 ? '' : `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`;

async function withTemp<T>(jobId: string, fn: (dir: string) => Promise<T>): Promise<T> {
  if (!SAFE_ID.test(jobId)) throw new Error('lake: unusable job id');
  const dir = await mkdtemp(join(tmpdir(), `lake-${jobId}-`));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * One lake part. With DuckDB on PATH: NDJSON → Parquet (zstd), run with an empty environment and with file
 * names built from the job id only. Without it: gzipped NDJSON. A part over MAX_OBJECT_BYTES throws.
 */
export async function writeLakePart(
  rows: readonly Record<string, unknown>[],
  columns: LakeColumns,
  deps: LakeDeps,
): Promise<{ bytes: Uint8Array; format: LakeFormat }> {
  for (const name of Object.keys(columns))
    if (!SAFE_COLUMN.test(name)) throw new Error('lake: bad column name');
  const duckdb = (deps.duckdb ?? findDuckdb)();
  let result: { bytes: Uint8Array; format: LakeFormat };
  if (!duckdb) {
    result = { bytes: gzipSync(ndjson(rows)), format: 'ndjson.gz' };
  } else {
    const run = deps.execFile ?? defaultExecFile;
    const cols = Object.entries(columns)
      .map(([name, type]) => `'${name}': '${type}'`)
      .join(', ');
    const bytes = await withTemp(deps.jobId, async (dir) => {
      const input = join(dir, 'in.ndjson');
      const output = join(dir, 'out.parquet');
      await writeFile(input, ndjson(rows));
      const sql = `COPY (SELECT * FROM read_json('${input}', format='newline_delimited', columns={${cols}})) TO '${output}' (FORMAT parquet, COMPRESSION zstd)`;
      await run(duckdb, ['-c', sql], { env: {}, maxBuffer: 1024 * 1024, timeout: DUCKDB_TIMEOUT_MS });
      return new Uint8Array(await readFile(output));
    });
    result = { bytes, format: 'parquet' };
  }
  deps.log?.('lake part', { format: result.format, bytes: result.bytes.byteLength });
  if (result.bytes.byteLength > MAX_OBJECT_BYTES)
    throw new Error('lake part is over the 50 MiB object limit; splitting parts is not built yet');
  return result;
}

/** Reverses `writeLakePart`: the rows of a part, in either format. */
export async function readLakePart(
  bytes: Uint8Array,
  format: LakeFormat,
  deps: LakeDeps,
): Promise<Record<string, unknown>[]> {
  let text: string;
  if (format === 'ndjson.gz') {
    text = gunzipSync(bytes).toString('utf8');
  } else {
    const duckdb = (deps.duckdb ?? findDuckdb)();
    if (!duckdb) throw new Error('lake: a Parquet part needs the duckdb CLI');
    const run = deps.execFile ?? defaultExecFile;
    text = await withTemp(deps.jobId, async (dir) => {
      const input = join(dir, 'in.parquet');
      const output = join(dir, 'out.ndjson');
      await writeFile(input, bytes);
      const sql = `COPY (SELECT * FROM read_parquet('${input}')) TO '${output}' (FORMAT json)`;
      await run(duckdb, ['-c', sql], { env: {}, maxBuffer: 1024 * 1024, timeout: DUCKDB_TIMEOUT_MS });
      return readFile(output, 'utf8');
    });
  }
  return text
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
