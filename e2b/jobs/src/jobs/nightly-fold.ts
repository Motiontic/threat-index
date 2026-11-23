import { gunzipSync } from 'node:zlib';
import { canIngest } from '@ti/core/licence';
import { SOURCES } from '@ti/sources/registry';
import { writeInbox } from '../lib/inbox.ts';
import { lakeObjectKey, writeLakePart } from '../lib/lake.ts';
import { dayStartMs, dayString, lakeDeps } from '../lib/work.ts';
import type { Job, JobContext, JobDeps } from '../types.ts';

const COLUMNS = {
  source: 'VARCHAR',
  run_id: 'VARCHAR',
  step: 'BIGINT',
  type: 'VARCHAR',
  item_id: 'VARCHAR',
  fetched_at: 'VARCHAR',
  content_type: 'VARCHAR',
  encoding: 'VARCHAR',
  body: 'VARCHAR',
} as const;

const asText = (v: unknown): string | null =>
  v === undefined || v === null ? null : typeof v === 'string' ? v : JSON.stringify(v);

/** Splits one receipt file's lines into lake rows. Lines that do not parse are counted and skipped. */
export function foldReceipt(
  source: string,
  fileName: string,
  text: string,
): { rows: Record<string, unknown>[]; bad: number } {
  const stem = fileName.replace(/\.ndjson\.gz$/, '');
  const at = stem.lastIndexOf('-');
  const step = Number(stem.slice(at + 1));
  if (at <= 0 || !Number.isInteger(step)) return { rows: [], bad: 1 };
  const runId = stem.slice(0, at);
  const rows: Record<string, unknown>[] = [];
  let bad = 0;
  let fetchedAt: string | null = null;
  let contentType: string | null = null;
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    let obj: Record<string, unknown>;
    try {
      const parsed = JSON.parse(line) as unknown;
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
        throw new Error('not an object');
      obj = parsed as Record<string, unknown>;
    } catch {
      bad++;
      continue;
    }
    if (obj.type === 'receipt') {
      fetchedAt = asText(obj.fetchedAt);
      contentType = asText(obj.contentType);
    }
    rows.push({
      source,
      run_id: runId,
      step,
      type: asText(obj.type),
      item_id: asText(obj.id),
      fetched_at: asText(obj.fetchedAt) ?? fetchedAt,
      content_type: asText(obj.contentType) ?? contentType,
      encoding: asText(obj.encoding),
      body: asText(obj.body),
    });
  }
  return { rows, bad };
}

/** Folds one UTC day of raw receipts into one lake part per source. Nothing goes to D1. */
export async function run(job: Job, ctx: JobContext, jobDeps: JobDeps = {}): Promise<void> {
  const now = (jobDeps.now ?? (() => new Date()))();
  const day = job.day ?? dayString(now.getTime() - 86_400_000);
  dayStartMs(day); // throws on a bad day
  const [yyyy, mm, dd] = day.split('-') as [string, string, string];
  const lake = lakeDeps(job.id, jobDeps, ctx.log);

  let parts = 0;
  let totalRows = 0;
  let totalBad = 0;
  for (const source of SOURCES) {
    if (!canIngest(source.licence)) continue;
    const rows: Record<string, unknown>[] = [];
    for await (const obj of ctx.api.list(`raw/${source.id}/${yyyy}/${mm}/${dd}/`)) {
      if (!obj.key.endsWith('.ndjson.gz')) continue;
      const bytes = await ctx.api.getObject(obj.key);
      if (!bytes) continue;
      let text: string;
      try {
        text = gunzipSync(bytes).toString('utf8');
      } catch {
        totalBad++;
        continue;
      }
      const folded = foldReceipt(source.id, obj.key.slice(obj.key.lastIndexOf('/') + 1), text);
      for (const r of folded.rows) rows.push(r);
      totalBad += folded.bad;
    }
    if (rows.length === 0) continue;
    const part = await writeLakePart(rows, COLUMNS, lake);
    await ctx.api.putObject(
      lakeObjectKey('raw', source.id, Number(yyyy), day, part.format),
      part.bytes,
      'application/octet-stream',
    );
    parts++;
    totalRows += rows.length;
    ctx.log('folded', { source: source.id, rows: rows.length, format: part.format });
  }
  ctx.log('fold done', { day, parts, rows: totalRows, bad: totalBad });
  await writeInbox(ctx.api, job.id, [], jobDeps.now);
}
