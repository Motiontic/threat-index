import { CADENCE_MS } from '@ti/core/cadence';
import { canIngest } from '@ti/core/licence';
import { readSourceSettings } from '@ti/core/settings';
import type { Cursor } from '@ti/core/types';
import { SOURCES, type SourceConfig } from '@ti/sources/registry';
import type { Env, JobMessage } from './env';

export const CADENCE_BY_CRON: Record<string, SourceConfig['cadence'][]> = {
  '0 */3 * * *': ['3h', 'with-cve-list'],
  '45 14 * * *': ['daily'],
  '30 2 * * *': [], // plans no source: the nightly fold and search index start from daily-jobs.ts
  '0 5 * * 1': ['weekly', 'monthly', 'quarterly'],
};

export { CADENCE_MS };

/** The cron whose ticks also start sources that have never had a successful run, whatever their cadence. */
export const FIRST_RUN_CRON = '0 */3 * * *';

/**
 * Most heavy sources without a success that one tick starts, on any cron. Heavy sources go to E2B jobs and ti-api allows
 * MAX_ACTIVE_JOBS (5) active jobs, two of them kept for deep queries, so 2 per tick leaves room: a new
 * environment starts its ~25 heavy sources within two days of ticks at most, while the others run at once.
 */
export const FIRST_RUN_HEAVY_PER_TICK = 2;

/** A source whose first load goes to an E2B job: `heavy`, the `heavy` pattern, or a git archive load. */
export function isHeavySource(s: SourceConfig): boolean {
  return s.heavy === true || s.pattern === 'heavy' || s.pattern === 'git';
}

/** Cron ticks drift a little; without this slack a 3-hourly source would run on every other tick. */
export const DUE_SLACK_MS = 30 * 60_000;

/** True with no success yet, or once a cadence (less the slack) has passed since the last one. */
export function isDue(cadence: SourceConfig['cadence'], lastSuccess: Date | null, at: Date): boolean {
  if (!lastSuccess) return true;
  return at.getTime() - lastSuccess.getTime() >= CADENCE_MS[cadence] - DUE_SLACK_MS;
}

export interface DueSource {
  source: SourceConfig;
  from: Cursor | null;
}

interface LatestRun {
  source_id: string;
  status: string;
  started_at: string;
}
interface LastSuccess {
  source_id: string;
  started_at: string;
}
interface CursorRow {
  source_id: string;
  kind: Cursor['kind'];
  value: string;
  etag: string | null;
}

/**
 * The sources this cron tick should run: the cron's cadence, licence and KV override allow ingest, the
 * last success is old enough, and no recent run still holds the source's cursor.
 */
export async function dueSources(
  env: Pick<Env, 'DB_CONTROL' | 'SETTINGS'>,
  cron: string,
  at: Date,
): Promise<DueSource[]> {
  const cadences = CADENCE_BY_CRON[cron] ?? [];
  const firstRunTick = cron === FIRST_RUN_CRON;
  // On the 3-hourly tick a source that can be fetched (it has a pull config) is also a candidate whatever
  // its cadence; the success check below keeps it out once it has had a first success.
  const candidates = SOURCES.filter(
    (s) => cadences.includes(s.cadence) || (firstRunTick && s.pull !== undefined),
  );
  if (candidates.length === 0) return [];

  const overrides = await readSourceSettings(
    env.SETTINGS,
    candidates.map((s) => s.id),
  );
  const allowed = candidates.filter((s) => canIngest(s.licence, overrides.get(s.id)?.ingest));
  if (allowed.length === 0) return [];

  // A run older than twice the longest cadence here can't change an answer: it is overdue either way.
  const window = 2 * Math.max(...allowed.map((s) => CADENCE_MS[s.cadence]));
  const since = new Date(at.getTime() - window).toISOString();
  const db = env.DB_CONTROL;
  const [latestRes, successRes, cursorRes] = await db.batch([
    db
      .prepare(
        'SELECT source_id, status, MAX(started_at) AS started_at FROM runs WHERE started_at >= ?1 GROUP BY source_id',
      )
      .bind(since),
    db
      .prepare(
        `SELECT source_id, MAX(started_at) AS started_at FROM runs
         WHERE started_at >= ?1 AND status IN ('ok', 'unchanged', 'heavy') GROUP BY source_id`,
      )
      .bind(since),
    db.prepare('SELECT source_id, kind, value, etag FROM cursors'),
  ]);
  const latest = new Map(((latestRes?.results ?? []) as LatestRun[]).map((r) => [r.source_id, r]));
  const success = new Map(
    ((successRes?.results ?? []) as LastSuccess[]).map((r) => [r.source_id, r.started_at]),
  );
  const cursors = new Map(((cursorRes?.results ?? []) as CursorRow[]).map((r) => [r.source_id, r]));

  const due: DueSource[] = [];
  const firstRunHeavy: SourceConfig[] = [];
  for (const source of allowed) {
    const inCadence = cadences.includes(source.cadence);
    const run = latest.get(source.id);
    if (run?.status === 'running') {
      const age = at.getTime() - Date.parse(run.started_at);
      // two runs must never share a cursor; a stuck first run of a slow-cadence source must not block it for months
      const hold = 2 * CADENCE_MS[inCadence ? source.cadence : '3h'];
      if (age < hold) continue;
    }
    const last = success.get(source.id);
    if (!inCadence && last) continue; // off-cadence candidates are only here for a first run
    if (!isDue(source.cadence, last ? new Date(last) : null, at)) continue;
    if (!last && isHeavySource(source)) firstRunHeavy.push(source);
    const c = cursors.get(source.id);
    const from: Cursor | null = c
      ? { kind: c.kind, value: c.value ?? '', ...(c.etag === null ? {} : { etag: c.etag }) }
      : null;
    due.push({ source, from });
  }
  // Cap every heavy source that has not yet succeeded, on every cron and whether or not an earlier attempt
  // failed: each start is an E2B job and ti-api allows MAX_ACTIVE_JOBS. Never-attempted sources go first,
  // then the least recently attempted, so a source that keeps failing cannot starve the others.
  const attempted = (id: string) => (latest.has(id) ? Date.parse(latest.get(id)?.started_at ?? '') : -1);
  const keep = new Set(
    [...firstRunHeavy]
      .sort((x, y) => attempted(x.id) - attempted(y.id))
      .slice(0, FIRST_RUN_HEAVY_PER_TICK)
      .map((x) => x.id),
  );
  const capped = new Set(firstRunHeavy.map((x) => x.id));
  return due.filter(({ source }) => !capped.has(source.id) || keep.has(source.id));
}

/** Queues one step-0 job per due source, then tells ti-notify when the 3-hourly run has been queued. */
export async function plan(event: ScheduledController, env: Env, deps: { newId(): string }): Promise<void> {
  const due = await dueSources(env, event.cron, new Date(event.scheduledTime));
  const messages = due.map(({ source, from }) => ({
    body: { sourceId: source.id, runId: deps.newId(), step: 0, from } satisfies JobMessage,
  }));
  for (let i = 0; i < messages.length; i += 100) {
    await env.JOBS.sendBatch(messages.slice(i, i + 100));
  }
  if (event.cron === '0 */3 * * *') await env.NOTIFY.send({ kind: 'run-finished', at: Date.now() });
}
