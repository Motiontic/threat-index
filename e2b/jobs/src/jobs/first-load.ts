import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { normaliseId } from '@ti/core/ids';
import type { InboxRow } from '@ti/core/inbox';
import { jobPrefix, lookupVulnKey } from '@ti/core/r2-keys';
import type { ParsedRecord } from '@ti/core/types';
import { candidateIds, type HubRecord } from '@ti/linker/hubs';
import { isAdvisoryRecord, isSignalRecord, isVulnRecord } from '@ti/linker/kinds';
import { type LinkDeps, link } from '@ti/linker/link';
import { type LinkTable, pkOf } from '@ti/linker/tables';
import { loadParser, type ParserModule } from '@ti/parsers/load';
import { globToRegExp } from '@ti/patterns/util';
import { SOURCE_BY_ID, type SourceConfig } from '@ti/sources/registry';
import type { RowTable } from '../client.ts';
import {
  applyCap,
  fetchItem,
  fetchItems,
  MAX_LIST_DOCS,
  readChangeList,
  readPair,
} from '../lib/changelist.ts';
import { download } from '../lib/download.ts';
import { fetchDocument, readTextLimited } from '../lib/http.ts';
import { writeInbox } from '../lib/inbox.ts';
import { lakeObjectKey, writeLakePart } from '../lib/lake.ts';
import { mapLimited } from '../lib/pool.ts';
import { readTarGz } from '../lib/tar.ts';
import { newUlid } from '../lib/ulid.ts';
import { lakeDeps, withScratch } from '../lib/work.ts';
import type { Job, JobContext, JobDeps } from '../types.ts';

const BATCH = 5000;
const ROW_TABLES: readonly string[] = ['vulns', 'advisories', 'signals'];

const isJsonPath = (url: string) => /\.json(\.gz)?$/.test(new URL(url).pathname);

const SHARDS_AT_ONCE = 8;
const LIST_PAGE_OBJECTS = 1000;
const LIST_MAX_PAGES = 5;
const SHARD_PREFIX = 'lookup/vuln/';

/**
 * The linker's read access in a sandbox: D1 rows through the API (cached; the three tables are paged together
 * on first use) and cold shards (listed once, then fetched in bulk by `prime`).
 */
export function sandboxLinkDeps(ctx: JobContext, now: () => Date) {
  const tables = new Map<string, Map<string, Record<string, unknown>>>();
  for (const t of ROW_TABLES) tables.set(t, new Map());
  let loading: Promise<void> | null = null;
  const loadAll = (): Promise<void> => {
    loading ??= Promise.all(
      ROW_TABLES.map(async (table) => {
        const rows = tables.get(table) as Map<string, Record<string, unknown>>;
        for await (const row of ctx.api.allRows(table as RowTable)) {
          const pk = pkOf(table as LinkTable, row);
          // A row a finished batch already merged wins over the one the API holds.
          if (!rows.has(pk)) rows.set(pk, row);
        }
      }),
    ).then(() => undefined);
    return loading;
  };

  const shards = new Map<string, Record<string, unknown> | null>();
  let listed: Set<string> | null = null;
  const listShards = async (): Promise<Set<string>> => {
    if (listed) return listed;
    const seen = new Set<string>();
    let n = 0;
    for await (const o of ctx.api.list(SHARD_PREFIX)) {
      if (++n > LIST_PAGE_OBJECTS * LIST_MAX_PAGES) break;
      seen.add(o.key);
    }
    listed = seen;
    ctx.log('shards listed', { shards: seen.size });
    return seen;
  };
  const loadShard = async (shardKey: string): Promise<void> => {
    if (shards.has(shardKey)) return;
    const bytes = await ctx.api.getObject(shardKey);
    let shard: Record<string, unknown> | null = null;
    if (bytes) {
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed))
        shard = parsed as Record<string, unknown>;
    }
    shards.set(shardKey, shard);
  };

  const deps: LinkDeps = {
    async read(table, keys) {
      if (!ROW_TABLES.includes(table)) return [];
      await loadAll();
      const rows = tables.get(table) as Map<string, Record<string, unknown>>;
      const out: Record<string, unknown>[] = [];
      for (const k of keys) {
        const hit = rows.get(pkOf(table as LinkTable, k));
        if (hit) out.push(hit);
      }
      return out;
    },
    async lookupCold(vulnKey) {
      const shardKey = lookupVulnKey(vulnKey);
      // A shard the listing did not show does not exist: no request.
      if (!shards.has(shardKey) && (await listShards()).has(shardKey)) await loadShard(shardKey);
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
  /** Before a batch: fetches, up to 8 at a time, the listed shards the batch's IDs fall in. */
  const prime = async (records: ParsedRecord[]): Promise<void> => {
    const exists = await listShards();
    const wanted = new Set<string>();
    for (const r of records) {
      if (!(isVulnRecord(r) || isAdvisoryRecord(r) || isSignalRecord(r))) continue;
      for (const id of candidateIds(r as HubRecord) ?? []) {
        const shardKey = lookupVulnKey(id);
        if (exists.has(shardKey) && !shards.has(shardKey)) wanted.add(shardKey);
      }
    }
    await mapLimited([...wanted], SHARDS_AT_ONCE, loadShard);
  };
  /** After a batch: its upserts and deletes become visible to the next batch. */
  const merge = (rows: InboxRow[]) => {
    for (const r of rows) {
      const t = tables.get(r.table);
      if (!t) continue;
      const pk = pkOf(r.table as LinkTable, r.row);
      if (r.op === 'delete') t.delete(pk);
      else t.set(pk, r.row);
    }
  };
  return { deps, merge, prime };
}

export type InputShape = 'file' | 'changelist' | 'change-item' | 'archive' | 'git-file';
export type LoadMode = 'first-load' | 'update';

/** Data files only, as in the git pattern (`packages/patterns/src/git.ts`). */
const DATA_EXTENSIONS = new Set(['json', 'csv', 'md', 'xml', 'yaml', 'yml', 'txt']);
const MAX_KEPT_FILES = 400_000;
const GIT_FILE_HOST = 'https://raw.githubusercontent.com';
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Which kind of input `url` is for this source. */
export function inputShape(source: SourceConfig, url: string): InputShape {
  if (source.pattern === 'changelist') {
    return url === source.pull?.changelist?.listUrl ? 'changelist' : 'change-item';
  }
  if (source.pattern === 'git') {
    const repo = source.pull?.git?.repo;
    if (
      repo &&
      new RegExp(`^https://github\\.com/${escapeRe(repo)}/archive/[0-9a-fA-F]{40}\\.tar\\.gz$`).test(url)
    )
      return 'archive';
    return 'git-file';
  }
  return 'file';
}

/** Parses documents one at a time. A throwing document is counted and skipped. */
function documentParser(parser: ParserModule) {
  const records: ParsedRecord[] = [];
  let docs = 0;
  let failed = 0;
  let firstError: unknown;
  return {
    records,
    feed(input: unknown): void {
      docs++;
      try {
        const parsed = parser.parse(input);
        for (const r of (Array.isArray(parsed) ? parsed : parsed.records) as ParsedRecord[]) records.push(r);
      } catch (err) {
        failed++;
        firstError ??= err;
      }
    },
    stats: () => ({ docs, failed }),
    /** Fails with the first error when every document threw. */
    finish(): void {
      if (docs > 0 && failed === docs)
        throw firstError instanceof Error ? firstError : new Error(String(firstError));
    },
  };
}

interface Request {
  cursor?: { kind?: string; value?: string };
  from?: { kind?: string; value?: string };
}

async function readRequest(ctx: JobContext, jobId: string): Promise<Request> {
  const bytes = await ctx.api.getObject(`${jobPrefix(jobId)}request.json`);
  if (!bytes) return {};
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    return typeof parsed === 'object' && parsed !== null ? (parsed as Request) : {};
  } catch {
    return {};
  }
}

/** Downloads a source's input (a file, a change list or an archive), parses it, links it and writes the load. */
export async function runLoad(
  job: Job,
  ctx: JobContext,
  jobDeps: JobDeps = {},
  mode: LoadMode = 'first-load',
): Promise<void> {
  if (!job.sourceId) throw new Error(`${job.kind} needs a sourceId`);
  const source = SOURCE_BY_ID.get(job.sourceId);
  if (!source) throw new Error(`unknown source ${job.sourceId}`);
  if (!source.parser) throw new Error(`source ${source.id} has no parser`);
  const url =
    job.url ??
    source.pull?.heavy?.url ??
    source.pull?.fingerprint?.url ??
    source.pull?.changelist?.listUrl ??
    source.urls?.[0];
  if (!url) throw new Error(`source ${source.id} has no URL`);
  const now = jobDeps.now ?? (() => new Date());
  const net = {
    ...(jobDeps.fetch ? { fetch: jobDeps.fetch } : {}),
    ...(jobDeps.sleep ? { sleep: jobDeps.sleep } : {}),
  };

  const shape = inputShape(source, url);
  const parser = await loadParser(source.parser);
  ctx.log('input', { shape, mode });
  let records: ParsedRecord[];

  if (shape === 'file') {
    records = await withScratch(job.id, async (dir) => {
      const dest = join(dir, 'source');
      const got = await download(url, dest, net);
      ctx.log('downloaded', { bytes: got.bytes });
      const text = await readFile(dest, 'utf8');
      const input = isJsonPath(url) || /json/i.test(got.contentType) ? (JSON.parse(text) as unknown) : text;
      const parsed = parser.parse(input);
      return (Array.isArray(parsed) ? parsed : parsed.records) as ParsedRecord[];
    });
  } else {
    const req = await readRequest(ctx, job.id);
    const target = readPair(req.cursor?.value);
    const docs = documentParser(parser);
    let oversize = 0;

    if (shape === 'changelist') {
      const cfg = source.pull?.changelist;
      if (!cfg) throw new Error(`source ${source.id} has no changelist config`);
      const from = mode === 'update' ? readPair(req.from?.value) : null;
      const listed = await withScratch(job.id, async (dir) => {
        const dest = join(dir, 'list');
        const got = await download(url, dest, net);
        ctx.log('downloaded', { bytes: got.bytes });
        return readChangeList(dest, cfg, { from, to: target });
      });
      const { lines, older } = applyCap(listed.lines, mode, MAX_LIST_DOCS);
      ctx.log('change list read', { lines: lines.length, older, unreadable: listed.unreadable });
      const out = await fetchItems(cfg, lines, { ...net, now }, (item) => docs.feed(item));
      oversize = out.oversize;
    } else if (shape === 'change-item') {
      const cfg = source.pull?.changelist;
      if (!cfg) throw new Error(`source ${source.id} has no changelist config`);
      if (!target) throw new Error('change-item needs a [time, ref] cursor in the request');
      const item = await fetchItem({ itemUrl: url }, { time: target[0], ref: target[1] }, net);
      if (item) docs.feed(item);
      else oversize = 1;
    } else if (shape === 'archive') {
      const git = source.pull?.git;
      if (!git) throw new Error(`source ${source.id} has no git config`);
      const include = git.include.map(globToRegExp);
      const res = (await fetchDocument(url, net)) as Response;
      let kept = 0;
      let filtered = 0;
      const tar = await readTarGz(res.body as ReadableStream<Uint8Array>, async (entry) => {
        const rel = entry.path.split('/').slice(1).join('/');
        const ext = /\.([A-Za-z0-9]+)$/.exec(rel)?.[1]?.toLowerCase();
        if (!rel || !ext || !DATA_EXTENSIONS.has(ext) || !include.some((re) => re.test(rel))) {
          filtered++;
          return;
        }
        if (++kept > MAX_KEPT_FILES) throw new Error('archive has too many files');
        docs.feed({ path: rel, status: 'added', text: await entry.text() });
      });
      oversize = 0;
      ctx.log('archive read', { entries: tar.files, kept, filtered, skipped: tar.skipped });
    } else {
      const git = source.pull?.git;
      if (!git) throw new Error(`source ${source.id} has no git config`);
      const marker = `/${git.repo}/`;
      const u = new URL(url);
      if (`${u.protocol}//${u.host}` !== GIT_FILE_HOST || !u.pathname.startsWith(marker))
        throw new Error('unexpected git file URL');
      // /<owner>/<name>/<sha>/<path…>
      const rest = u.pathname.slice(marker.length).split('/');
      const path = decodeURIComponent(rest.slice(1).join('/'));
      if (!path) throw new Error('unexpected git file URL');
      const res = (await fetchDocument(url, net)) as Response;
      const text = await readTextLimited(res);
      if (text === null) oversize = 1;
      else docs.feed({ path, status: 'modified', text });
    }

    const stats = docs.stats();
    ctx.log('documents parsed', { documents: stats.docs, failed: stats.failed, oversize });
    if (stats.docs === 0 && oversize > 0) throw new Error('every document was over the size limit');
    docs.finish();
    records = docs.records;
  }
  ctx.log('parsed', { records: records.length });

  const { deps, merge, prime } = sandboxLinkDeps(ctx, now);
  const rows: InboxRow[] = [];
  let docs = 0;
  let skipped = 0;
  for (let i = 0; i < records.length; i += BATCH) {
    const batch = records.slice(i, i + BATCH);
    await prime(batch);
    const result = await link(batch, deps);
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
  if (records.length === 0) ctx.log('no records: no lake part');
  else {
    const part = await writeLakePart(
      lakeRows,
      { source: 'VARCHAR', job_id: 'VARCHAR', n: 'BIGINT', record: 'VARCHAR' },
      lakeDeps(job.id, jobDeps, ctx.log),
    );
    const key = lakeObjectKey('records', source.id, now().getUTCFullYear(), job.id, part.format);
    await ctx.api.putObject(key, part.bytes, 'application/octet-stream');
    ctx.log('lake part written', { format: part.format, bytes: part.bytes.byteLength });
  }

  const { chunks } = await writeInbox(ctx.api, job.id, rows, now);
  ctx.log('inbox written', { chunks, rows: rows.length });
}

/** Downloads a source's input, parses it, links it into hot-set rows and writes the lake part and the inbox. */
export const run = (job: Job, ctx: JobContext, jobDeps: JobDeps = {}): Promise<void> =>
  runLoad(job, ctx, jobDeps, 'first-load');
