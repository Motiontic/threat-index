/**
 * deep-query: answers one allow-listed question from the lake with DuckDB. The request is
 * `jobs/<id>/request.json` (validated again here); parameters reach DuckDB only through `params.json`, never
 * through SQL text. Result: `jobs/<id>/result.json`, plus an empty manifest because `complete` needs one.
 */
import { execFile as nodeExecFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { canIngest } from '@ti/core/licence';
import { SOURCES } from '@ti/sources/registry';
import {
  type DeepQuery,
  type DeepTemplate,
  MAX_RESULT_ROWS,
  validateDeepQuery,
} from '../../../../apps/api/src/lib/deep-templates.ts';
import { writeInbox } from '../lib/inbox.ts';
import { findDuckdb } from '../lib/lake.ts';
import { withScratch } from '../lib/work.ts';
import type { Job, JobContext, JobDeps, RunJob } from '../types.ts';

export const MAX_SCAN_OBJECTS = 2000;
export const MAX_SCAN_BYTES = 512 * 1024 * 1024;
export const MAX_RESULT_BYTES = 5 * 1024 * 1024;
const SQL_ROW_LIMIT = 5000;
const FETCH_PARALLEL = 8;
const DUCKDB_TIMEOUT_MS = 120_000;
const DUCKDB_MAX_BUFFER = 1024 * 1024;

export interface ScanObject {
  key: string;
  size: number;
}
export type PartFormat = 'parquet' | 'ndjson.gz';
export interface LakeRow {
  source: string;
  job_id: string;
  record: string;
}
export interface ResultRow {
  [k: string]: unknown;
}
export interface Finished {
  rows: ResultRow[];
  truncated: boolean;
  sources: string[];
}

const fail = (code: string): Error => new Error(`deep-query: ${code}`);
const partFormat = (key: string): PartFormat | null =>
  key.endsWith('.parquet') ? 'parquet' : key.endsWith('.ndjson.gz') ? 'ndjson.gz' : null;

/** Prefixes to list, from the template only. */
export function scanPrefixes(query: DeepQuery): string[] {
  switch (query.template) {
    case 'kev-additions':
      return ['lake/records/cisa-kev/'];
    case 'epss-history': {
      const from = Number((query.params.from as string).slice(0, 4));
      const to = Number((query.params.to as string).slice(0, 4));
      const out: string[] = [];
      for (let y = from; y <= to; y++) out.push(`lake/epss/epss/${y}/`);
      return out;
    }
    default:
      return SOURCES.filter((s) => canIngest(s.licence) && s.licence !== 'link').map(
        (s) => `lake/records/${s.id}/`,
      );
  }
}

/** The parts to read, from a listing of every object under `scanPrefixes`. Throws `scan_too_large`. */
export function planScan(query: DeepQuery, objects: readonly ScanObject[]): ScanObject[] {
  const prefixes = scanPrefixes(query);
  const keep = objects.filter((o) => {
    if (!prefixes.some((p) => o.key.startsWith(p)) || partFormat(o.key) === null) return false;
    if (query.template !== 'epss-history') return true;
    const m = /\/part-(\d{4}-\d{2}-\d{2})\.(parquet|ndjson\.gz)$/.exec(o.key);
    return (
      m !== null &&
      (m[1] as string) >= (query.params.from as string) &&
      (m[1] as string) <= (query.params.to as string)
    );
  });
  const bytes = keep.reduce((n, o) => n + o.size, 0);
  if (keep.length > MAX_SCAN_OBJECTS || bytes > MAX_SCAN_BYTES) throw fail('scan_too_large');
  return keep;
}

/**
 * The SQL for a template. Constant text plus a `parts` view over generated file names (`p-<n>.<ext>` in
 * `dir`); parameters come only from `params.json`. `dir` and the names are made by this job, never by input.
 */
export function buildSql(template: DeepTemplate, files: readonly string[], dir: string): string {
  const q = (s: string) => `'${s.replace(/'/g, "''")}'`;
  const list = (names: string[]) => `[${names.map((n) => q(join(dir, n))).join(', ')}]`;
  const parquet = files.filter((f) => f.endsWith('.parquet'));
  const nd = files.filter((f) => f.endsWith('.ndjson.gz'));
  const isEpss = template === 'epss-history';
  const cols = isEpss
    ? `{cve: 'VARCHAR', epss: 'DOUBLE', percentile: 'DOUBLE', model_version: 'VARCHAR', score_date: 'VARCHAR'}`
    : `{source: 'VARCHAR', job_id: 'VARCHAR', n: 'BIGINT', record: 'VARCHAR'}`;
  const selects: string[] = [];
  if (parquet.length > 0) selects.push(`SELECT * FROM read_parquet(${list(parquet)}, union_by_name=true)`);
  if (nd.length > 0)
    selects.push(`SELECT * FROM read_json(${list(nd)}, format='newline_delimited', columns=${cols})`);
  const parts =
    selects.length > 0 ? selects.join(' UNION ALL BY NAME ') : `SELECT NULL::VARCHAR AS record WHERE false`;
  let where: string;
  switch (template) {
    case 'cve-history':
      where = `contains(upper(record), p.cve)`;
      break;
    case 'package-advisories':
      where = `contains(record, '"affected"') AND contains(lower(record), lower(p.package))`;
      break;
    case 'company-breaches':
      where = `contains(record, '"noticeId"')`;
      break;
    case 'kev-additions':
      where = `contains(record, '"exploited_wild"') AND json_extract_string(record, '$.firstSeen') BETWEEN p."from" AND p."to"`;
      break;
    case 'epss-history':
      where = `upper(parts.cve) = p.cve AND substr(score_date, 1, 10) BETWEEN p."from" AND p."to"`;
      break;
  }
  const output = q(join(dir, 'out.ndjson'));
  const input = q(join(dir, 'params.json'));
  return [
    `CREATE VIEW parts AS ${parts};`,
    `CREATE VIEW p AS SELECT * FROM read_json(${input});`,
    `COPY (SELECT parts.* FROM parts, p WHERE ${where} LIMIT ${SQL_ROW_LIMIT}) TO ${output} (FORMAT json);`,
  ].join('\n');
}

type Rec = Record<string, unknown>;
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const upperList = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => str(x).toUpperCase()) : []);

/** The exact rule for each template. SQL may only narrow what this accepts. */
export function matches(query: DeepQuery, record: Rec, source = ''): boolean {
  const p = query.params;
  switch (query.template) {
    case 'cve-history': {
      const cve = p.cve as string;
      return (
        str(record.key).toUpperCase() === cve ||
        str(record.vulnKey).toUpperCase() === cve ||
        upperList(record.aliases).includes(cve)
      );
    }
    case 'package-advisories': {
      if (typeof record.sourceId !== 'string' || !Array.isArray(record.affected)) return false;
      const eco = (p.ecosystem as string).toLowerCase();
      return (record.affected as Rec[]).some(
        (a) => a && str(a.ecosystem).toLowerCase() === eco && a.name === p.package,
      );
    }
    case 'company-breaches': {
      if (typeof record.noticeId !== 'string') return false;
      const c = p.company as string;
      if (c.startsWith('cik:') || c.startsWith('domain:')) return record.companyKey === c;
      return str(record.rawName).toLowerCase().includes(c.toLowerCase());
    }
    case 'kev-additions': {
      const day = str(record.firstSeen).slice(0, 10);
      return (
        (source === '' || source === 'cisa-kev') &&
        record.kind === 'exploited_wild' &&
        day >= (p.from as string) &&
        day <= (p.to as string)
      );
    }
    case 'epss-history':
      return false; // EPSS rows are not records
  }
}

function identity(record: Rec): string {
  const s = str(record.source);
  if (typeof record.sourceId === 'string') return `adv|${s}|${record.sourceId}`;
  if (typeof record.noticeId === 'string') return `notice|${s}|${record.noticeId}`;
  if (typeof record.vulnKey === 'string' && typeof record.kind === 'string')
    return `sig|${s}|${record.vulnKey}|${record.kind}|${str(record.ref)}`;
  if (typeof record.key === 'string') return `vuln|${s}|${record.key}`;
  return `other|${s}|${JSON.stringify(record)}`;
}
const sortStamp = (r: Rec): string => str(r.modified) || str(r.firstSeen) || str(r.published);

/** Parses, filters with `matches`, dedupes, sorts and caps. `rows` are lake rows, or EPSS rows for `epss-history`. */
export function finish(query: DeepQuery, rows: readonly Rec[], maxRows = MAX_RESULT_ROWS): Finished {
  let out: ResultRow[];
  if (query.template === 'epss-history') {
    const byDay = new Map<string, ResultRow>();
    for (const r of rows) {
      if (str(r.cve).toUpperCase() !== query.params.cve) continue;
      const day = str(r.score_date).slice(0, 10);
      if (day < (query.params.from as string) || day > (query.params.to as string)) continue;
      byDay.set(day, { day, epss: r.epss, percentile: r.percentile, model: r.model_version });
    }
    out = [...byDay.values()].sort((a, b) => (a.day as string).localeCompare(b.day as string));
    const truncated = out.length > maxRows;
    return { rows: out.slice(0, maxRows), truncated, sources: ['epss'] };
  }

  type Kept = { source: string; jobId: string; record: Rec; text: string };
  const distinct = new Map<string, Kept>(); // exact duplicates collapse onto the newest job
  for (const r of rows) {
    const text = str(r.record);
    const source = str(r.source);
    let record: Rec;
    try {
      const parsed = JSON.parse(text) as unknown;
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) continue;
      record = parsed as Rec;
    } catch {
      continue;
    }
    if (!matches(query, record, source)) continue;
    const dupe = `${source}\u0000${text}`;
    const jobId = str(r.job_id);
    const cur = distinct.get(dupe);
    if (!cur || jobId > cur.jobId) distinct.set(dupe, { source, jobId, record, text });
  }
  const kept = [...distinct.values()];
  let chosen = kept;
  if (query.template !== 'cve-history') {
    const newest = new Map<string, Kept>();
    for (const k of kept) {
      const id = identity(k.record);
      const cur = newest.get(id);
      if (!cur || k.jobId > cur.jobId) newest.set(id, k);
    }
    chosen = [...newest.values()];
  }
  chosen.sort(
    (a, b) =>
      a.source.localeCompare(b.source) ||
      sortStamp(a.record).localeCompare(sortStamp(b.record)) ||
      a.text.localeCompare(b.text),
  );
  const truncated = chosen.length > maxRows;
  out = chosen.slice(0, maxRows).map((k) => ({ source: k.source, jobId: k.jobId, record: k.record }));
  const sources = [...new Set(out.map((r) => r.source as string))].sort();
  return { rows: out, truncated, sources };
}

const defaultExec = (
  file: string,
  args: string[],
  opts: { env: Record<string, string>; maxBuffer: number; timeout: number },
) =>
  new Promise<unknown>((resolve, reject) => {
    nodeExecFile(file, args, opts, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });

const parseLines = (text: string): Rec[] =>
  text
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as Rec);

export const run: RunJob = async (job: Job, ctx: JobContext, deps: JobDeps = {}) => {
  const now = deps.now ?? (() => new Date());
  const t0 = Date.now();
  const req = await ctx.api.getObject(`jobs/${job.id}/request.json`);
  let stored: Record<string, unknown> | null = null;
  try {
    stored = req ? (JSON.parse(new TextDecoder().decode(req)) as Record<string, unknown>) : null;
  } catch {
    stored = null;
  }
  const checked = validateDeepQuery(
    stored ? { template: stored.template, params: stored.params } : null,
    now(),
  );
  if (!checked.ok) throw fail('invalid_params');
  const query = checked.query;

  const listed: ScanObject[] = [];
  for (const prefix of scanPrefixes(query)) for await (const o of ctx.api.list(prefix)) listed.push(o);
  const plan = planScan(query, listed);
  const tList = Date.now();
  const bytes = plan.reduce((n, o) => n + o.size, 0);

  const duckdb = (deps.duckdb ?? findDuckdb)();
  const exec = deps.execFile ?? defaultExec;

  const {
    rows: found,
    tFetch,
    tQuery,
  } = await withScratch(job.id, async (dir) => {
    const names = plan.map((o, n) => `p-${n}.${partFormat(o.key) === 'parquet' ? 'parquet' : 'ndjson.gz'}`);
    let next = 0;
    const worker = async () => {
      for (;;) {
        const n = next++;
        const o = plan[n];
        if (!o) return;
        const body = await ctx.api.getObject(o.key);
        if (!body) throw fail('query_failed');
        await writeFile(join(dir, names[n] as string), body);
      }
    };
    await Promise.all(Array.from({ length: Math.min(FETCH_PARALLEL, plan.length) }, worker));
    const fetched = Date.now();

    let rows: Rec[] = [];
    if (plan.length > 0) {
      if (duckdb) {
        await writeFile(join(dir, 'params.json'), JSON.stringify(query.params));
        const sql = buildSql(query.template, names, dir);
        try {
          await exec(duckdb, ['-c', sql], {
            env: {},
            maxBuffer: DUCKDB_MAX_BUFFER,
            timeout: DUCKDB_TIMEOUT_MS,
          });
          rows = parseLines(await readFile(join(dir, 'out.ndjson'), 'utf8'));
        } catch {
          throw fail('query_failed');
        }
      } else {
        if (names.some((n) => n.endsWith('.parquet'))) {
          ctx.log('duckdb missing');
          throw fail('query_failed');
        }
        for (const n of names) {
          try {
            rows.push(...parseLines(gunzipSync(await readFile(join(dir, n))).toString('utf8')));
          } catch {
            throw fail('query_failed');
          }
        }
      }
    }
    return { rows, tFetch: fetched, tQuery: Date.now() };
  });

  const done = finish(query, found);
  let { rows } = done;
  let truncated = done.truncated;
  const build = () =>
    JSON.stringify({
      template: query.template,
      rows,
      rowCount: rows.length,
      truncated,
      sources: done.sources,
      scanned: { objects: plan.length, bytes },
      tookMs: Date.now() - t0,
    });
  let body = build();
  while (new TextEncoder().encode(body).length > MAX_RESULT_BYTES && rows.length > 0) {
    rows = rows.slice(0, Math.floor(rows.length / 2));
    truncated = true;
    body = build();
  }
  await ctx.api.putObject(`jobs/${job.id}/result.json`, body, 'application/json');
  await writeInbox(ctx.api, job.id, [], now);
  ctx.log('deep query done', {
    template: query.template,
    objects: plan.length,
    bytes,
    rows: rows.length,
    truncated,
    duckdb: duckdb !== null,
    listMs: tList - t0,
    fetchMs: tFetch - tList,
    queryMs: tQuery - tFetch,
  });
};
