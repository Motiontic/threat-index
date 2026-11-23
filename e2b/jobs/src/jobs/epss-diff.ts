import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { normaliseId } from '@ti/core/ids';
import type { InboxRow } from '@ti/core/inbox';
import { epssBand } from '@ti/linker/detect';
import { download } from '../lib/download.ts';
import { writeInbox } from '../lib/inbox.ts';
import { type LakeFormat, lakeObjectKey, readLakePart, writeLakePart } from '../lib/lake.ts';
import { deterministicUlid } from '../lib/ulid.ts';
import { dayStartMs, dayString, lakeDeps, withScratch, YMD } from '../lib/work.ts';
import type { Job, JobContext, JobDeps } from '../types.ts';

/** FIRST's data page (Nov 2026). The host redirects, so `download` follows redirects. */
export const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
export const MAX_BAD_RATIO = 0.01;
export const MAX_CHANGES = 50_000;
const CVE = /^CVE-\d{4}-\d{4,}$/i;

export interface EpssRow {
  cve: string;
  epss: number;
  percentile: number;
  model_version: string;
  score_date: string;
}

/**
 * Parses `#model_version:v…,score_date:…` then the `cve,epss,percentile` CSV. Rows that do not parse are
 * counted; the caller decides how many are too many.
 */
export function parseEpss(text: string): { rows: EpssRow[]; bad: number; day: string } {
  const lines = text.split(/\r?\n/);
  let i = 0;
  while (i < lines.length && lines[i]?.trim() === '') i++;
  const comment = lines[i] ?? '';
  if (!comment.startsWith('#')) throw new Error('EPSS file has no #model_version comment line');
  const meta: Record<string, string> = {};
  for (const part of comment.slice(1).split(',')) {
    const at = part.indexOf(':');
    if (at > 0) meta[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  const model = meta.model_version;
  const scoreDate = meta.score_date;
  if (!model || !scoreDate) throw new Error('EPSS comment line lacks model_version or score_date');
  const day = scoreDate.slice(0, 10);
  if (!YMD.test(day)) throw new Error('EPSS score_date is not a date');
  i++;
  if ((lines[i] ?? '').trim() !== 'cve,epss,percentile')
    throw new Error('EPSS file has an unexpected header');
  i++;

  const rows: EpssRow[] = [];
  let bad = 0;
  for (; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line.trim() === '') continue;
    const [cve, epss, pct, ...extra] = line.split(',');
    const e = Number(epss);
    const p = Number(pct);
    if (
      extra.length > 0 ||
      !cve ||
      !CVE.test(cve) ||
      epss === '' ||
      pct === '' ||
      !Number.isFinite(e) ||
      !Number.isFinite(p) ||
      e < 0 ||
      e > 1 ||
      p < 0 ||
      p > 1
    ) {
      bad++;
      continue;
    }
    rows.push({
      cve: cve.toUpperCase(),
      epss: e,
      percentile: p,
      model_version: model,
      score_date: scoreDate,
    });
  }
  return { rows, bad, day };
}

/** Today's EPSS scores go to lake/. Hot CVEs that changed band since yesterday become `changes` rows. */
export async function run(job: Job, ctx: JobContext, jobDeps: JobDeps = {}): Promise<void> {
  if (job.sourceId !== 'epss') throw new Error('epss-diff needs sourceId "epss"');
  const url = job.url ?? EPSS_URL;
  const { rows, bad, day } = await withScratch(job.id, async (dir) => {
    const dest = join(dir, 'epss.csv');
    const got = await download(url, dest, {
      ...(jobDeps.fetch ? { fetch: jobDeps.fetch } : {}),
      ...(jobDeps.sleep ? { sleep: jobDeps.sleep } : {}),
    });
    ctx.log('downloaded', { bytes: got.bytes });
    return parseEpss(await readFile(dest, 'utf8'));
  });
  const total = rows.length + bad;
  ctx.log('parsed', { rows: rows.length, bad, day });
  if (rows.length === 0) throw new Error('EPSS file has no usable rows');
  if (bad / total > MAX_BAD_RATIO) throw new Error(`EPSS file has too many bad rows (${bad} of ${total})`);

  const dayMs = dayStartMs(day);
  const year = Number(day.slice(0, 4));
  const lake = lakeDeps(job.id, jobDeps, ctx.log);
  const part = await writeLakePart(
    rows as unknown as Record<string, unknown>[],
    { cve: 'VARCHAR', epss: 'DOUBLE', percentile: 'DOUBLE', model_version: 'VARCHAR', score_date: 'VARCHAR' },
    lake,
  );
  // The same key on a rerun: the part is overwritten.
  await ctx.api.putObject(
    lakeObjectKey('epss', 'epss', year, day, part.format),
    part.bytes,
    'application/octet-stream',
  );
  ctx.log('lake part written', { format: part.format, bytes: part.bytes.byteLength });

  // Yesterday's part, in whichever format it was written.
  const prevDay = dayString(dayMs - 86_400_000);
  let prev: Record<string, unknown>[] | null = null;
  for (const format of ['parquet', 'ndjson.gz'] as LakeFormat[]) {
    const bytes = await ctx.api.getObject(
      lakeObjectKey('epss', 'epss', Number(prevDay.slice(0, 4)), prevDay, format),
    );
    if (bytes) {
      prev = await readLakePart(bytes, format, lake);
      break;
    }
  }

  const changes: InboxRow[] = [];
  if (!prev) {
    ctx.log('no previous day', { day: prevDay });
  } else {
    const before = new Map(prev.map((r) => [normaliseId(String(r.cve)), Number(r.epss)]));
    const today = new Map(rows.map((r) => [normaliseId(r.cve), r.epss]));
    let hot = 0;
    for await (const v of ctx.api.allRows('vulns')) {
      if (v.hot !== 1 && v.hot !== true) continue;
      hot++;
      const key = normaliseId(String(v.key));
      const was = before.get(key);
      const is = today.get(key);
      if (was === undefined || is === undefined || epssBand(was) === epssBand(is)) continue;
      changes.push({
        table: 'changes',
        op: 'upsert',
        row: {
          id: deterministicUlid(dayMs, `epss_band:${key}:${day}`),
          entity_key: key,
          kind: 'epss_band',
          old: String(was),
          new: String(is),
          at: `${day}T00:00:00Z`,
          source: 'epss',
        },
      });
      if (changes.length > MAX_CHANGES) throw new Error('epss-diff found too many changes');
    }
    ctx.log('diffed', { hot, changes: changes.length });
  }
  changes.sort((a, b) => String(a.row.entity_key).localeCompare(String(b.row.entity_key)));
  const { chunks } = await writeInbox(ctx.api, job.id, changes, jobDeps.now);
  ctx.log('inbox written', { chunks, rows: changes.length });
}
