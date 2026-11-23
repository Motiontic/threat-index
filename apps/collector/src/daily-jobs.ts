import type { JobRequest } from '@ti/core/control';
import { readSourceSettings } from '@ti/core/settings';
import type { Env } from './env';
import type { GlobalJobRequest, startHeavyJob } from './heavy';

export type DailyKind = 'nightly-fold' | 'search-index' | 'epss-diff';

/** The E2B jobs each cron starts (the source crons are in planner.ts). */
export const DAILY_JOBS: Record<string, readonly DailyKind[]> = {
  '30 2 * * *': ['nightly-fold', 'search-index'],
  '45 14 * * *': ['epss-diff'],
};

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DAY_MS = 86_400_000;
const YMD = /^\d{4}-\d{2}-\d{2}$/;

/**
 * A ULID-shaped job id for `kind` on `day` (`YYYY-MM-DD`, UTC): the time part is UTC midnight of the day and
 * the random part is the first 80 bits of SHA-256(`${kind}:${day}`). The same kind and day always give the
 * same id, so a retried or doubled cron gets `200 existing` from ti-api and never a second sandbox.
 */
export async function dailyJobId(kind: DailyKind, day: string): Promise<string> {
  const ms = Date.parse(`${day}T00:00:00Z`);
  if (!YMD.test(day) || Number.isNaN(ms)) throw new Error('dailyJobId: day must be YYYY-MM-DD');
  let time = BigInt(ms);
  let out = '';
  for (let i = 0; i < 10; i++) {
    out = CROCKFORD[Number(time & 31n)] + out;
    time >>= 5n;
  }
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${kind}:${day}`)),
  );
  let bits = 0n;
  for (const b of digest.subarray(0, 10)) bits = (bits << 8n) | BigInt(b);
  let rand = '';
  for (let i = 0; i < 16; i++) {
    rand = CROCKFORD[Number(bits & 31n)] + rand;
    bits >>= 5n;
  }
  return out + rand;
}

const ymd = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export interface DailyDeps {
  startJob: typeof startHeavyJob;
  log: (msg: string, extra?: Record<string, unknown>) => void;
  /** The clock for signing (default: now). The job's day always comes from `at`. */
  now?: () => Date;
}

/**
 * Starts the E2B jobs for `cron`. `at` is the cron's scheduled time (never `Date.now()`), so the day, and with
 * it every job id, is the same on a retry. Each job starts on its own; the first error is rethrown at the end.
 */
export async function startDailyJobs(cron: string, at: Date, env: Env, deps: DailyDeps): Promise<void> {
  const kinds = DAILY_JOBS[cron] ?? [];
  const today = ymd(at.getTime());
  const yesterday = ymd(at.getTime() - DAY_MS);
  const errors: unknown[] = [];

  for (const kind of kinds) {
    try {
      let req: JobRequest | GlobalJobRequest;
      if (kind === 'nightly-fold') {
        req = {
          kind,
          reason: 'nightly',
          requestId: await dailyJobId(kind, yesterday),
          day: yesterday,
        };
      } else if (kind === 'search-index') {
        req = { kind, reason: 'nightly', requestId: await dailyJobId(kind, today) };
      } else {
        const settings = (await readSourceSettings(env.SETTINGS, ['epss'])).get('epss');
        if (settings?.ingest === false) {
          deps.log('daily job skipped', { kind, reason: 'ingest is off' });
          continue;
        }
        req = {
          kind,
          sourceId: 'epss',
          reason: 'daily',
          requestId: await dailyJobId(kind, today),
        };
      }
      const out = await deps.startJob(env, req, (deps.now ?? (() => new Date()))());
      deps.log('daily job started', { kind, requestId: req.requestId, jobId: out.jobId });
    } catch (err) {
      errors.push(err);
      deps.log('daily job failed to start', {
        kind,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  if (errors.length > 0) throw errors[0];
}
