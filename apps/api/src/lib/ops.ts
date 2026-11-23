import { D1_DAILY_WRITE_LIMIT, EMAIL_DAILY_CAP, utcDay } from '@ti/core/budget';
import { CADENCE_MS } from '@ti/core/cadence';
import { canIngest } from '@ti/core/licence';
import type { OpsReport } from '@ti/core/ops';
import { readSourceSettings } from '@ti/core/settings';
import { SOURCES } from '@ti/sources/registry';
import type { Bindings } from './env';

export type OpsEnv = Pick<Bindings, 'DB_CONTROL' | 'DB_USERS' | 'SETTINGS' | 'LOAD' | 'JOBS' | 'JOBS_DLQ'>;

const DAY_MS = 86_400_000;
const QUEUE_TIMEOUT_MS = 1000;
const LIST_LIMIT = 20;

interface SourceRow {
  source_id: string;
  last_success: string | null;
  last_started: string | null;
  failed: number;
  dead: number;
}

async function queueStats(
  name: OpsReport['queues'][number]['name'],
  queue: { metrics(): Promise<{ backlogCount: number; oldestMessageTimestamp?: Date }> } | undefined,
): Promise<OpsReport['queues'][number]> {
  const none = { name, backlog: null, oldest: null };
  if (!queue || typeof queue.metrics !== 'function') return none;
  try {
    const m = await Promise.race([
      queue.metrics(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), QUEUE_TIMEOUT_MS)),
    ]);
    return {
      name,
      backlog: m.backlogCount,
      oldest: m.oldestMessageTimestamp ? new Date(m.oldestMessageTimestamp).toISOString() : null,
    };
  } catch {
    return none;
  }
}

export async function buildOpsReport(env: OpsEnv, now: Date): Promise<OpsReport> {
  const day = utcDay(now);
  const since = new Date(now.getTime() - 7 * DAY_MS).toISOString();
  const db = env.DB_CONTROL;
  const [perSource, latest, budgetRes, byStatus, recent, dead] = await db.batch([
    db
      .prepare(
        `SELECT source_id,
           MAX(CASE WHEN status IN ('ok','unchanged','heavy') THEN started_at END) AS last_success,
           SUM(CASE WHEN started_at >= ?1 AND status IN ('failed','timed_out') THEN 1 ELSE 0 END) AS failed,
           SUM(CASE WHEN started_at >= ?1 AND error LIKE 'dead-lettered%' THEN 1 ELSE 0 END) AS dead
         FROM runs GROUP BY source_id`,
      )
      .bind(since),
    db.prepare('SELECT source_id, status, MAX(started_at) AS started_at FROM runs GROUP BY source_id'),
    db.prepare('SELECT d1_writes, queue_ops, r2_class_a FROM budget WHERE day = ?1').bind(day),
    db.prepare('SELECT status, COUNT(*) AS n FROM jobs WHERE created_at >= ?1 GROUP BY status').bind(since),
    db.prepare(
      `SELECT id, kind, status, source_id, created_at, finished_at, error FROM jobs
         ORDER BY created_at DESC LIMIT ${LIST_LIMIT}`,
    ),
    db.prepare(
      `SELECT id, source_id, finished_at, error FROM runs WHERE error LIKE 'dead-lettered%'
         ORDER BY COALESCE(finished_at, started_at) DESC LIMIT ${LIST_LIMIT}`,
    ),
  ]);
  const emailRow = await env.DB_USERS.prepare('SELECT sent FROM email_log WHERE day = ?1')
    .bind(day)
    .first<{ sent: number }>();
  const [overrides, jobsQ, dlqQ, loadQ] = await Promise.all([
    readSourceSettings(
      env.SETTINGS,
      SOURCES.map((s) => s.id),
    ).catch(() => new Map()),
    queueStats('ti-jobs', env.JOBS),
    queueStats('ti-jobs-dlq', env.JOBS_DLQ),
    queueStats('ti-load', env.LOAD),
  ]);

  const stats = new Map(((perSource?.results ?? []) as unknown as SourceRow[]).map((r) => [r.source_id, r]));
  const lastRuns = new Map(
    ((latest?.results ?? []) as unknown as { source_id: string; status: string; started_at: string }[]).map(
      (r) => [r.source_id, r],
    ),
  );
  const sources: OpsReport['sources'] = SOURCES.map((s) => {
    const st = stats.get(s.id);
    const run = lastRuns.get(s.id);
    const ingest = canIngest(s.licence, overrides.get(s.id)?.ingest);
    const lastSuccess = st?.last_success ?? null;
    const late =
      ingest && (lastSuccess === null || now.getTime() - Date.parse(lastSuccess) > 2 * CADENCE_MS[s.cadence]);
    return {
      id: s.id,
      cadence: s.cadence,
      ingest,
      lastSuccess,
      lastRun: run ? { status: run.status, startedAt: run.started_at } : null,
      failed7d: st?.failed ?? 0,
      deadLettered7d: st?.dead ?? 0,
      late,
    };
  });

  const b = (budgetRes?.results?.[0] ?? {}) as {
    d1_writes?: number;
    queue_ops?: number;
    r2_class_a?: number;
  };
  const counts: Record<string, number> = {};
  for (const r of (byStatus?.results ?? []) as unknown as { status: string; n: number }[])
    counts[r.status] = r.n;
  type JobRow = {
    id: string;
    kind: string;
    status: string;
    source_id: string | null;
    created_at: string;
    finished_at: string | null;
    error: string | null;
  };
  return {
    generatedAt: now.toISOString(),
    sources,
    budget: {
      day,
      d1Writes: b.d1_writes ?? 0,
      d1Limit: D1_DAILY_WRITE_LIMIT,
      emailsSent: emailRow?.sent ?? 0,
      emailCap: EMAIL_DAILY_CAP,
      queueOps: b.queue_ops ?? 0,
      r2ClassA: b.r2_class_a ?? 0,
    },
    queues: [jobsQ, dlqQ, loadQ],
    jobs: {
      byStatus: counts,
      recent: ((recent?.results ?? []) as unknown as JobRow[]).map((j) => ({
        id: j.id,
        kind: j.kind,
        status: j.status,
        // For deep-query this column holds the user id.
        sourceId: j.kind === 'deep-query' ? null : j.source_id,
        createdAt: j.created_at,
        finishedAt: j.finished_at,
        error: j.error === null ? null : j.error.slice(0, 200),
      })),
    },
    deadLetters: (
      (dead?.results ?? []) as unknown as {
        id: string;
        source_id: string;
        finished_at: string | null;
        error: string;
      }[]
    ).map((r) => ({
      runId: r.id,
      sourceId: r.source_id,
      finishedAt: r.finished_at,
      error: r.error.slice(0, 200),
    })),
  };
}
