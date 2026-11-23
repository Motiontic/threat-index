import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { normaliseId } from '@ti/core/ids';
import type { InboxRow } from '@ti/core/inbox';
import { lookupVulnKey } from '@ti/core/r2-keys';
import type { ParsedRecord } from '@ti/core/types';
import { type LinkDeps, link } from '@ti/linker/link';
import { type LinkTable, pkOf } from '@ti/linker/tables';
import { loadParser } from '@ti/parsers/load';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import type { RowTable } from '../client.ts';
import { download } from '../lib/download.ts';
import { writeInbox } from '../lib/inbox.ts';
import { lakeObjectKey, writeLakePart } from '../lib/lake.ts';
import { newUlid } from '../lib/ulid.ts';
import { lakeDeps, withScratch } from '../lib/work.ts';
import type { Job, JobContext, JobDeps } from '../types.ts';

const BATCH = 5000;
const ROW_TABLES: readonly string[] = ['vulns', 'advisories', 'signals'];

const isJsonPath = (url: string) => /\.json(\.gz)?$/.test(new URL(url).pathname);

/** The linker's read access in a sandbox: D1 rows through the API (cached, paged once per table) and cold shards. */
export function sandboxLinkDeps(ctx: JobContext, now: () => Date) {
  const tables = new Map<string, { loaded: boolean; rows: Map<string, Record<string, unknown>> }>();
  const shards = new Map<string, Record<string, unknown> | null>();
  const entry = (table: string) => {
    let e = tables.get(table);
    if (!e) {
      e = { loaded: false, rows: new Map() };
      tables.set(table, e);
    }
    return e;
  };
  const deps: LinkDeps = {
    async read(table, keys) {
      if (!ROW_TABLES.includes(table)) return [];
      const e = entry(table);
      if (!e.loaded) {
        // A row a finished batch already merged wins over the one the API holds.
        for await (const row of ctx.api.allRows(table as RowTable)) {
          const pk = pkOf(table as LinkTable, row);
          if (!e.rows.has(pk)) e.rows.set(pk, row);
        }
        e.loaded = true;
      }
      const out: Record<string, unknown>[] = [];
      for (const k of keys) {
        const hit = e.rows.get(pkOf(table as LinkTable, k));
        if (hit) out.push(hit);
      }
      return out;
    },
    async lookupCold(vulnKey) {
      const shardKey = lookupVulnKey(vulnKey);
      if (!shards.has(shardKey)) {
        const bytes = await ctx.api.getObject(shardKey);
        let shard: Record<string, unknown> | null = null;
        if (bytes) {
          const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
          if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed))
            shard = parsed as Record<string, unknown>;
        }
        shards.set(shardKey, shard);
      }
      const shard = shards.get(shardKey);
      const key = normaliseId(vulnKey);
      const row = shard && Object.hasOwn(shard, key) ? shard[key] : null;
      return typeof row === 'object' && row !== null && !Array.isArray(row)
        ? (row as Record<string, unknown>)
        : null;
    },
    now,
    newId: () => newUlid(now().getTime()),
  };
  /** After a batch: its upserts and deletes become visible to the next batch. */
  const merge = (rows: InboxRow[]) => {
    for (const r of rows) {
      if (!ROW_TABLES.includes(r.table)) continue;
      const e = entry(r.table);
      const pk = pkOf(r.table as LinkTable, r.row);
      if (r.op === 'delete') e.rows.delete(pk);
      else e.rows.set(pk, r.row);
    }
  };
  return { deps, merge };
}

/** Downloads a source's file, parses it, links it into hot-set rows and writes the lake part and the inbox. */
export async function run(job: Job, ctx: JobContext, jobDeps: JobDeps = {}): Promise<void> {
  if (!job.sourceId) throw new Error('first-load needs a sourceId');
  const source = SOURCE_BY_ID.get(job.sourceId);
  if (!source) throw new Error(`unknown source ${job.sourceId}`);
  if (!source.parser) throw new Error(`source ${source.id} has no parser`);
  const url = job.url ?? source.pull?.heavy?.url ?? source.pull?.fingerprint?.url ?? source.urls?.[0];
  if (!url) throw new Error(`source ${source.id} has no URL`);
  const now = jobDeps.now ?? (() => new Date());

  const records = await withScratch(job.id, async (dir) => {
    const dest = join(dir, 'source');
    const got = await download(url, dest, {
      ...(jobDeps.fetch ? { fetch: jobDeps.fetch } : {}),
      ...(jobDeps.sleep ? { sleep: jobDeps.sleep } : {}),
    });
    ctx.log('downloaded', { bytes: got.bytes });
    const text = await readFile(dest, 'utf8');
    const input = isJsonPath(url) || /json/i.test(got.contentType) ? (JSON.parse(text) as unknown) : text;
    const parser = await loadParser(source.parser as string);
    const parsed = parser.parse(input);
    return (Array.isArray(parsed) ? parsed : parsed.records) as ParsedRecord[];
  });
  ctx.log('parsed', { records: records.length });

  const { deps, merge } = sandboxLinkDeps(ctx, now);
  const rows: InboxRow[] = [];
  let docs = 0;
  let skipped = 0;
  for (let i = 0; i < records.length; i += BATCH) {
    const result = await link(records.slice(i, i + BATCH), deps);
    merge(result.rows);
    for (const r of result.rows) rows.push(r);
    docs += result.docs.length;
    skipped += result.skipped;
  }
  ctx.log('linked', { rows: rows.length, docs, skipped });

  const lakeRows = records.map((record, n) => ({
    source: source.id,
    job_id: job.id,
    n,
    record: JSON.stringify(record),
  }));
  const part = await writeLakePart(
    lakeRows,
    { source: 'VARCHAR', job_id: 'VARCHAR', n: 'BIGINT', record: 'VARCHAR' },
    lakeDeps(job.id, jobDeps, ctx.log),
  );
  const key = lakeObjectKey('records', source.id, now().getUTCFullYear(), job.id, part.format);
  await ctx.api.putObject(key, part.bytes, 'application/octet-stream');
  ctx.log('lake part written', { format: part.format, bytes: part.bytes.byteLength });

  const { chunks } = await writeInbox(ctx.api, job.id, rows, now);
  ctx.log('inbox written', { chunks, rows: rows.length });
}
