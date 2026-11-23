// Guard for GET /v1/admin/ops. Copies known fields only and caps every list, so a bad answer cannot flood a page.
import type { OpsReport } from '@ti/core/ops';
import { arr, bool, GuardError, num, obj, optStr, str } from './guards';

export const MAX_OPS_SOURCES = 200;
export const MAX_OPS_JOBS = 20;
export const MAX_OPS_DEAD_LETTERS = 20;

const QUEUES = new Set(['ti-jobs', 'ti-jobs-dlq', 'ti-load']);
const cut = (s: string, n = 200) => s.slice(0, n);
const orNull = (v: string | undefined) => v ?? null;

function nullableNum(o: Record<string, unknown>, key: string, what: string): number | null {
  const v = o[key];
  if (v === null || v === undefined) return null;
  return num(o, key, what);
}

export function guardOps(value: unknown): OpsReport {
  const o = obj(value, 'ops');
  const budget = obj(o.budget, 'ops.budget');
  const jobs = obj(o.jobs, 'ops.jobs');
  const byStatus: Record<string, number> = {};
  for (const [k, v] of Object.entries(obj(jobs.byStatus, 'ops.jobs.byStatus')).slice(0, 20)) {
    if (typeof v !== 'number' || !Number.isFinite(v)) throw new GuardError('ops.jobs.byStatus: not a number');
    byStatus[cut(k, 40)] = v;
  }
  return {
    generatedAt: str(o, 'generatedAt', 'ops'),
    sources: arr(o, 'sources', 'ops')
      .slice(0, MAX_OPS_SOURCES)
      .map((raw) => {
        const s = obj(raw, 'ops.sources[]');
        const lastRun = s.lastRun === null || s.lastRun === undefined ? null : obj(s.lastRun, 'ops.lastRun');
        return {
          id: cut(str(s, 'id', 'source'), 80),
          cadence: cut(str(s, 'cadence', 'source'), 40),
          ingest: bool(s, 'ingest', 'source'),
          lastSuccess: orNull(optStr(s, 'lastSuccess', 'source')),
          lastRun: lastRun
            ? {
                status: cut(str(lastRun, 'status', 'lastRun'), 40),
                startedAt: str(lastRun, 'startedAt', 'lastRun'),
              }
            : null,
          failed7d: num(s, 'failed7d', 'source'),
          deadLettered7d: num(s, 'deadLettered7d', 'source'),
          late: bool(s, 'late', 'source'),
        };
      }),
    budget: {
      day: str(budget, 'day', 'budget'),
      d1Writes: num(budget, 'd1Writes', 'budget'),
      d1Limit: num(budget, 'd1Limit', 'budget'),
      emailsSent: num(budget, 'emailsSent', 'budget'),
      emailCap: num(budget, 'emailCap', 'budget'),
      queueOps: num(budget, 'queueOps', 'budget'),
      r2ClassA: num(budget, 'r2ClassA', 'budget'),
    },
    queues: arr(o, 'queues', 'ops')
      .slice(0, 3)
      .map((raw) => {
        const q = obj(raw, 'ops.queues[]');
        const name = str(q, 'name', 'queue');
        if (!QUEUES.has(name)) throw new GuardError('ops.queues[].name: unknown queue');
        return {
          name: name as OpsReport['queues'][number]['name'],
          backlog: nullableNum(q, 'backlog', 'queue'),
          oldest: orNull(optStr(q, 'oldest', 'queue')),
        };
      }),
    jobs: {
      byStatus,
      recent: arr(jobs, 'recent', 'ops.jobs')
        .slice(0, MAX_OPS_JOBS)
        .map((raw) => {
          const j = obj(raw, 'ops.jobs.recent[]');
          const error = optStr(j, 'error', 'job');
          return {
            id: cut(str(j, 'id', 'job'), 80),
            kind: cut(str(j, 'kind', 'job'), 40),
            status: cut(str(j, 'status', 'job'), 40),
            sourceId: orNull(optStr(j, 'sourceId', 'job')),
            createdAt: str(j, 'createdAt', 'job'),
            finishedAt: orNull(optStr(j, 'finishedAt', 'job')),
            error: error === undefined ? null : cut(error),
          };
        }),
    },
    deadLetters: arr(o, 'deadLetters', 'ops')
      .slice(0, MAX_OPS_DEAD_LETTERS)
      .map((raw) => {
        const d = obj(raw, 'ops.deadLetters[]');
        return {
          runId: cut(str(d, 'runId', 'dead'), 80),
          sourceId: cut(str(d, 'sourceId', 'dead'), 80),
          finishedAt: orNull(optStr(d, 'finishedAt', 'dead')),
          error: cut(str(d, 'error', 'dead')),
        };
      }),
  };
}
