/**
 * affected-backfill: fills `package_advisories` and `affected` for the history already loaded.
 *
 * It reads R2 only (`lake/records/<source>/` and `raw/<source>/`) and writes through the MTI API. Its sandbox
 * is created with a network limit that reaches the API alone; the job checks that before it does anything.
 * It loads at steady priority under its own daily cap (`DAILY_WRITE_CAP`), apart from the first-load cap.
 *
 * Runbook
 * 1. Deploy this change.
 * 2. Refresh the lake. For each package source, start `first-load`
 *    (`{ kind: 'first-load', sourceId, requestId, reason, url? }`). Git sources need `url` set to the archive of
 *    the branch's head commit. Send no `cursor`, so the source's cursor stays where it is. Run them on days
 *    with no other first-load.
 * 3. Dry run. Start `affected-backfill` (`POST /internal/jobs { kind: 'affected-backfill', reason }`). Read
 *    `jobs/<id>/counts.json`. `oldFormat` should be near 0 for the git sources. For `osv`, `debian` and
 *    `ubuntu` it counts records outside the refresh's newest 10,000.
 * 4. Fill. Start the job once a day until every source is done. A second start on the same UTC day writes only
 *    the rest of that day's cap. Do not run it on a day a first-load is loading: the meter is shared.
 * 5. Check staging (see SPEC.md, acceptance criterion 14).
 *
 * Recovery. If a run fails after logging `state written`, its chunks may not have been queued. Set that
 * source's `after` back to the run's logged `from`. Every write is idempotent.
 */
import { gunzipSync } from 'node:zlib';
import { normaliseId } from '@ti/core/ids';
import type { InboxRow } from '@ti/core/inbox';
import { MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import { canIngest } from '@ti/core/licence';
import type { AdvisoryRecord, ParsedRecord, RangeType } from '@ti/core/types';
import { affectedRows, packageCost, packageWrites, type SkipReason } from '@ti/linker/affected';
import { isAdvisoryRecord } from '@ti/linker/kinds';
import { loadParser, type ParserModule } from '@ti/parsers/load';
import { SOURCES, type SourceConfig } from '@ti/sources/registry';
import { checkEgress } from '../lib/egress.ts';
import { writeInboxChunks } from '../lib/inbox.ts';
import { type LakeFormat, readLakePart } from '../lib/lake.ts';
import { lakeDeps } from '../lib/work.ts';
import type { Job, JobContext, JobDeps } from '../types.ts';

export const PACKAGE_PARSERS = [
  'osv-ghsa',
  'osv',
  'osv-malicious',
  'cve-json5',
  'osv-debian',
  'osv-ubuntu',
] as const;
export const DAILY_WRITE_CAP = 600_000;
export const RUN_BUDGET_MS = 40 * 60 * 1000;
export const MAX_SOURCE_BYTES = 8 * 1024 ** 3;
export const MAX_COPIES = 2_000_000;
export const STATE_KEY = 'lake/state/affected-backfill/state.json';

export interface SourceState {
  after: string | null;
  done: boolean;
  completedAt: string | null;
  records: number;
  rows: number;
  writes: number;
}
export interface BackfillState {
  v: 1;
  countedBy: string | null;
  day: string;
  writesToday: number;
  sources: Record<string, SourceState>;
}
export interface BackfillLimits {
  dailyWriteCap: number;
  runBudgetMs: number;
}
const DEFAULT_LIMITS: BackfillLimits = { dailyWriteCap: DAILY_WRITE_CAP, runBudgetMs: RUN_BUDGET_MS };

export interface BackfillCounts {
  jobId: string;
  createdAt: string;
  dailyWriteCap: number;
  sources: Record<
    string,
    {
      copies: number;
      latest: number;
      oldFormat: number;
      parseFailures: number;
      packageRecords: number;
      rows: number;
      writes: number;
      byEcosystem: Record<string, { rows: number; writes: number }>;
      byRangeType: Record<RangeType, number>;
      skipped: Partial<Record<SkipReason, number>>;
    }
  >;
  total: { rows: number; writes: number; days: number };
}

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const isDay = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);

/** Checks every field by hand (the sandbox package has no zod). Throws on anything unexpected. */
export function parseState(bytes: Uint8Array): BackfillState {
  const bad = (why: string): never => {
    throw new Error(`affected-backfill: malformed state (${why})`);
  };
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return bad('not JSON');
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return bad('not an object');
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) bad('v');
  if (o.countedBy !== null && typeof o.countedBy !== 'string') bad('countedBy');
  if (!isDay(o.day)) bad('day');
  if (!isInt(o.writesToday)) bad('writesToday');
  if (typeof o.sources !== 'object' || o.sources === null || Array.isArray(o.sources)) bad('sources');
  const sources: Record<string, SourceState> = {};
  for (const [id, s] of Object.entries(o.sources as Record<string, unknown>)) {
    if (typeof s !== 'object' || s === null || Array.isArray(s)) return bad(`source ${id}`);
    const e = s as Record<string, unknown>;
    if (e.after !== null && typeof e.after !== 'string') bad(`${id}.after`);
    if (typeof e.done !== 'boolean') bad(`${id}.done`);
    if (
      e.completedAt !== null &&
      (typeof e.completedAt !== 'string' || Number.isNaN(Date.parse(e.completedAt)))
    )
      bad(`${id}.completedAt`);
    if (!isInt(e.records) || !isInt(e.rows) || !isInt(e.writes)) bad(`${id} counters`);
    sources[id] = {
      after: e.after as string | null,
      done: e.done as boolean,
      completedAt: e.completedAt as string | null,
      records: e.records as number,
      rows: e.rows as number,
      writes: e.writes as number,
    };
  }
  return {
    v: 1,
    countedBy: o.countedBy as string | null,
    day: o.day as string,
    writesToday: o.writesToday as number,
    sources,
  };
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ULID_RE = /[0-7][0-9A-HJKMNP-TV-Z]{25}/;
/** The time in a ULID's first 10 characters, ms. NaN when it is not one. */
function ulidTime(id: string): number {
  if (!/^[0-7][0-9A-HJKMNP-TV-Z]{9}/.test(id)) return Number.NaN;
  let t = 0;
  for (const ch of id.slice(0, 10)) t = t * 32 + CROCKFORD.indexOf(ch);
  return t;
}

interface Copy {
  record: AdvisoryRecord;
  modified: string;
  origin: string; // receipt run id or lake job id: time-ordered ULIDs
  from: 'lake' | 'raw';
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function packageSources(): SourceConfig[] {
  const order = PACKAGE_PARSERS as readonly string[];
  return SOURCES.filter(
    // `pull` is unset only for sources that arrive inside another source's files (cisa-vulnrichment).
    (s) => s.parser !== undefined && order.includes(s.parser) && s.pull !== undefined && canIngest(s.licence),
  ).sort((a, b) => order.indexOf(a.parser as string) - order.indexOf(b.parser as string));
}

interface History {
  latest: Map<string, Copy>;
  copies: number;
  oldFormat: number;
  parseFailures: number;
}

async function loadHistory(
  source: SourceConfig,
  parser: ParserModule,
  job: Job,
  ctx: JobContext,
  jobDeps: JobDeps,
): Promise<History> {
  const h: History = { latest: new Map(), copies: 0, oldFormat: 0, parseFailures: 0 };
  const lakeFiles: { key: string; size: number }[] = [];
  const rawFiles: { key: string; size: number }[] = [];
  let bytes = 0;
  for await (const o of ctx.api.list(`lake/records/${source.id}/`)) {
    lakeFiles.push(o);
    bytes += o.size;
  }
  for await (const o of ctx.api.list(`raw/${source.id}/`)) {
    rawFiles.push(o);
    bytes += o.size;
  }
  if (bytes > MAX_SOURCE_BYTES)
    throw new Error(`affected-backfill: ${source.id} is over ${MAX_SOURCE_BYTES} bytes`);

  const keep = (record: AdvisoryRecord, origin: string, from: Copy['from']) => {
    h.copies++;
    if (h.copies > MAX_COPIES)
      throw new Error(`affected-backfill: ${source.id} is over ${MAX_COPIES} copies`);
    const modified = typeof record.modified === 'string' ? record.modified : '';
    const key = `${record.source}\u0000${normaliseId(record.sourceId)}`;
    const have = h.latest.get(key);
    // Highest `modified`; on a tie the later origin.
    if (!have || modified > have.modified || (modified === have.modified && origin >= have.origin))
      h.latest.set(key, { record, modified, origin, from });
  };

  for (const f of lakeFiles) {
    const format: LakeFormat | null = f.key.endsWith('.parquet')
      ? 'parquet'
      : f.key.endsWith('.ndjson.gz')
        ? 'ndjson.gz'
        : null;
    const origin = /part-([0-9A-Z]{26})/.exec(f.key)?.[1];
    if (!format || !origin) continue;
    const body = await ctx.api.getObject(f.key);
    if (!body) continue;
    const rows = await readLakePart(body, format, lakeDeps(job.id, jobDeps, ctx.log));
    for (const row of rows) {
      let rec: unknown;
      try {
        rec = typeof row.record === 'string' ? JSON.parse(row.record) : row.record;
      } catch {
        continue;
      }
      if (typeof rec !== 'object' || rec === null || !isAdvisoryRecord(rec as ParsedRecord)) continue;
      const a = rec as AdvisoryRecord;
      if (typeof a.reviewed !== 'boolean') {
        h.copies++;
        h.oldFormat++;
        continue;
      }
      keep(a, typeof row.job_id === 'string' && row.job_id ? row.job_id : origin, 'lake');
    }
  }

  for (const f of rawFiles) {
    const run = /\/([0-9A-Z]{26})-\d+\.ndjson\.gz$/.exec(f.key)?.[1];
    if (!run || !ULID_RE.test(run)) continue;
    const body = await ctx.api.getObject(f.key);
    if (!body) continue;
    let text: string;
    try {
      text = gunzipSync(body).toString('utf8');
    } catch {
      h.parseFailures++;
      continue;
    }
    for (const line of text.split('\n')) {
      if (!line.startsWith('{')) continue;
      let item: { type?: unknown; body?: unknown };
      try {
        item = JSON.parse(line) as typeof item;
      } catch {
        continue;
      }
      if (item.type !== 'item' || item.body === undefined) continue;
      try {
        const parsed = parser.parse(item.body);
        const records = (Array.isArray(parsed) ? parsed : parsed.records) as ParsedRecord[];
        for (const r of records) if (isAdvisoryRecord(r)) keep(r, run, 'raw');
      } catch {
        h.parseFailures++;
      }
    }
  }
  return h;
}

const emptyCounts = (): BackfillCounts['sources'][string] => ({
  copies: 0,
  latest: 0,
  oldFormat: 0,
  parseFailures: 0,
  packageRecords: 0,
  rows: 0,
  writes: 0,
  byEcosystem: {},
  byRangeType: { SEMVER: 0, ECOSYSTEM: 0, EXACT: 0 },
  skipped: {},
});

function freshSource(): SourceState {
  return { after: null, done: false, completedAt: null, records: 0, rows: 0, writes: 0 };
}

export async function backfill(
  job: Job,
  ctx: JobContext,
  jobDeps: JobDeps = {},
  limits: BackfillLimits = DEFAULT_LIMITS,
): Promise<void> {
  const now = jobDeps.now ?? (() => new Date());
  // 1. Egress check.
  await checkEgress('affected-backfill', jobDeps);

  // 2. State, and the clock.
  const started = now().getTime();
  const today = now().toISOString().slice(0, 10);
  const stored = await ctx.api.getObject(STATE_KEY);
  const state: BackfillState = stored
    ? parseState(stored)
    : { v: 1, countedBy: null, day: today, writesToday: 0, sources: {} };
  if (state.day !== today) {
    state.day = today;
    state.writesToday = 0;
  }
  const dry = state.countedBy === null;

  const counts: BackfillCounts = {
    jobId: job.id,
    createdAt: now().toISOString(),
    dailyWriteCap: limits.dailyWriteCap,
    sources: {},
    total: { rows: 0, writes: 0, days: 0 },
  };

  const chunks: InboxRow[][] = [];
  let current: InboxRow[] = [];
  const flush = () => {
    if (current.length > 0) chunks.push(current);
    current = [];
  };
  let remaining = limits.dailyWriteCap - state.writesToday;
  let stopped = false;
  let emitted = 0;

  for (const source of packageSources()) {
    if (stopped) break;
    const mine = state.sources[source.id] ?? freshSource();
    // 2. Picked: not done, or done with a lake part newer than `completedAt`. Re-opened sources write only
    // records whose latest copy comes from such a part.
    let reopenAfter: number | null = null;
    if (!dry && mine.completedAt !== null) reopenAfter = Date.parse(mine.completedAt);
    if (!dry && mine.done && mine.completedAt !== null) {
      let newer = false;
      for await (const o of ctx.api.list(`lake/records/${source.id}/`)) {
        const id = /part-([0-9A-Z]{26})/.exec(o.key)?.[1];
        if (id && ulidTime(id) > (reopenAfter as number)) {
          newer = true;
          break;
        }
      }
      if (!newer) continue;
      mine.done = false;
      mine.after = null;
    }
    if (!dry && mine.done) continue;

    // 3. History.
    const parser = await loadParser(source.parser as string);
    const h = await loadHistory(source, parser, job, ctx, jobDeps);
    let latest = [...h.latest.values()];
    if (!dry && reopenAfter !== null) {
      const since = reopenAfter;
      latest = latest.filter((c) => c.from === 'lake' && ulidTime(c.origin) > since);
    }
    latest.sort((a, b) => cmp(normaliseId(a.record.sourceId), normaliseId(b.record.sourceId)));

    if (dry) {
      // 4. Dry run: count everything, write nothing.
      const c = emptyCounts();
      c.copies = h.copies;
      c.latest = h.latest.size;
      c.oldFormat = h.oldFormat;
      c.parseFailures = h.parseFailures;
      for (const copy of latest) {
        const plan = affectedRows(copy.record);
        for (const [why, n] of Object.entries(plan.skipped) as [SkipReason, number][])
          c.skipped[why] = (c.skipped[why] ?? 0) + n;
        const rows = packageWrites(copy.record, plan, { ranges: [] });
        if (rows.length === 0) continue;
        c.packageRecords++;
        c.rows += rows.length;
        c.writes += packageCost(rows);
        for (const r of rows) {
          if (r.table !== 'affected') continue;
          const base = String(r.row.ecosystem).split(':')[0] as string;
          const e = c.byEcosystem[base] ?? { rows: 0, writes: 0 };
          c.byEcosystem[base] = e;
          e.rows++;
          e.writes += packageCost([r]);
          c.byRangeType[r.row.range_type as RangeType]++;
        }
      }
      counts.sources[source.id] = c;
      counts.total.rows += c.rows;
      counts.total.writes += c.writes;
      state.sources[source.id] = mine;
      ctx.log('counted', { source: source.id, latest: c.latest, rows: c.rows, units: c.writes });
      continue;
    }

    // 5. Write run.
    const from = mine.after;
    let records = 0;
    let rowsOut = 0;
    let units = 0;
    let finished = true;
    for (const copy of latest) {
      const id = normaliseId(copy.record.sourceId);
      if (mine.after !== null && cmp(id, mine.after) <= 0) continue;
      if (now().getTime() - started >= limits.runBudgetMs) {
        finished = false;
        break;
      }
      const rows = packageWrites(copy.record, affectedRows(copy.record), { ranges: [] });
      const cost = packageCost(rows);
      if (cost > remaining) {
        finished = false;
        break;
      }
      if (rows.length > 0) {
        if (current.length + rows.length > MAX_ROWS_PER_CHUNK) flush();
        current.push(...rows);
        remaining -= cost;
        units += cost;
        rowsOut += rows.length;
        records++;
      }
      mine.after = id;
    }
    mine.records += records;
    mine.rows += rowsOut;
    mine.writes += units;
    emitted += units;
    if (finished) {
      mine.done = true;
      mine.completedAt = now().toISOString();
    } else stopped = true;
    state.sources[source.id] = mine;
    ctx.log('source', {
      source: source.id,
      from,
      to: mine.after,
      records,
      rows: rowsOut,
      units,
      done: finished,
    });
  }
  flush();

  // 6. Chunks, then the manifest, then the state.
  if (dry) {
    counts.total.days = Math.ceil(counts.total.writes / limits.dailyWriteCap);
    await ctx.api.putObject(`jobs/${job.id}/counts.json`, JSON.stringify(counts), 'application/json');
    state.countedBy = job.id;
    ctx.log('counted', { rows: counts.total.rows, units: counts.total.writes, days: counts.total.days });
  } else {
    state.writesToday += emitted;
  }
  await writeInboxChunks(ctx.api, job.id, chunks, now);
  await ctx.api.putObject(STATE_KEY, JSON.stringify(state), 'application/json');
  ctx.log('state written', { chunks: chunks.length, units: emitted });
}

export const run = (job: Job, ctx: JobContext, jobDeps: JobDeps = {}): Promise<void> =>
  backfill(job, ctx, jobDeps);
