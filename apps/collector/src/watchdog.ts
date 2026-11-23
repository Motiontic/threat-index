import { EmailMessage } from 'cloudflare:email';
import { D1_DAILY_WRITE_LIMIT, EMAIL_DAILY_CAP, utcDay } from '@ti/core/budget';
import { canIngest } from '@ti/core/licence';
import { readSourceSettings, UNKNOWN_FIELDS_PREFIX } from '@ti/core/settings';
import { SOURCES } from '@ti/sources/registry';
import type { Env } from './env';
import { CADENCE_MS } from './planner';
import { buildRawEmail, type Finding, formatReport } from './report';

export interface WatchdogDeps {
  now(): Date;
  newId(): string;
  log(msg: string, extra?: Record<string, unknown>): void;
}

const DAY = 86_400_000;
const STALE_JOB_MS = 60 * 60_000;
const MAX_ROWS = 1000;
const CADENCE_DROP_CHECKED = new Set(['3h', 'daily']);
const ADDRESS = /^[^\s@<>"]+@[^\s@<>"]+$/;

/**
 * The daily health check (§5): looks for the findings below, emails the report (also when it is clear, as a
 * heartbeat) and returns the findings. The report only goes out when OPS_EMAIL, OPS_EMAIL_TO and
 * OPS_EMAIL_FROM are all set; otherwise the counts are logged and the email is skipped.
 */
export async function runWatchdog(env: Env, deps: WatchdogDeps): Promise<Finding[]> {
  const now = deps.now();
  const findings = [
    ...(await lateSources(env, now)),
    ...(await droppedSources(env, now)),
    ...(await unknownFields(env, now)),
    ...(await budgetUse(env, now)),
    ...(await failedRuns(env, now)),
    ...(await stuckJobs(env, now)),
  ];
  await sendReport(env, findings, deps);
  return findings;
}

async function lateSources(env: Env, now: Date): Promise<Finding[]> {
  const overrides = await readSourceSettings(
    env.SETTINGS,
    SOURCES.map((s) => s.id),
  );
  const res = await env.DB_CONTROL.prepare(
    `SELECT source_id,
       MAX(CASE WHEN status IN ('ok', 'unchanged', 'heavy') THEN started_at END) AS last_success,
       MIN(started_at) AS first_run
     FROM runs GROUP BY source_id`,
  ).all<{ source_id: string; last_success: string | null; first_run: string }>();
  const rows = new Map(res.results.map((r) => [r.source_id, r]));
  const out: Finding[] = [];
  for (const s of SOURCES) {
    if (!canIngest(s.licence, overrides.get(s.id)?.ingest)) continue;
    const limit = 2 * CADENCE_MS[s.cadence];
    const r = rows.get(s.id);
    if (!r) {
      out.push({ kind: 'late', subject: s.id, detail: 'never run' });
    } else if (r.last_success) {
      if (now.getTime() - Date.parse(r.last_success) > limit) {
        out.push({ kind: 'late', subject: s.id, detail: `no success since ${r.last_success}` });
      }
    } else if (now.getTime() - Date.parse(r.first_run) > limit) {
      out.push({ kind: 'late', subject: s.id, detail: `no success since its first run at ${r.first_run}` });
    }
  }
  return out;
}

async function droppedSources(env: Env, now: Date): Promise<Finding[]> {
  const mid = new Date(now.getTime() - 7 * DAY).toISOString();
  const start = new Date(now.getTime() - 14 * DAY).toISOString();
  const res = await env.DB_CONTROL.prepare(
    `SELECT source_id,
       SUM(CASE WHEN started_at >= ?1 THEN found ELSE 0 END) AS recent,
       SUM(CASE WHEN started_at < ?1 THEN found ELSE 0 END) AS before
     FROM runs WHERE started_at >= ?2 GROUP BY source_id`,
  )
    .bind(mid, start)
    .all<{ source_id: string; recent: number; before: number }>();
  const checked = new Set(SOURCES.filter((s) => CADENCE_DROP_CHECKED.has(s.cadence)).map((s) => s.id));
  return res.results
    .filter((r) => checked.has(r.source_id) && r.before >= 50 && r.recent < 0.8 * r.before)
    .map((r) => ({
      kind: 'drop',
      subject: r.source_id,
      detail: `found ${r.recent} in the last 7 days, ${r.before} in the 7 days before`,
    }));
}

async function unknownFields(env: Env, now: Date): Promise<Finding[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.SETTINGS.list({ prefix: UNKNOWN_FIELDS_PREFIX, cursor });
    keys.push(...page.keys.map((k) => k.name));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && keys.length < MAX_ROWS);

  const since = now.getTime() - DAY;
  const out: Finding[] = [];
  for (let i = 0; i < keys.length; i += 100) {
    const got = await env.SETTINGS.get(keys.slice(i, i + 100), 'text');
    for (const [key, raw] of got) {
      if (!raw) continue;
      let v: { fields?: unknown; lastSeen?: unknown };
      try {
        v = JSON.parse(raw);
      } catch {
        continue;
      }
      if (typeof v.lastSeen !== 'string' || Date.parse(v.lastSeen) < since) continue;
      const fields = Array.isArray(v.fields) ? v.fields.filter((f) => typeof f === 'string') : [];
      out.push({
        kind: 'unknown-fields',
        subject: key.slice(UNKNOWN_FIELDS_PREFIX.length),
        detail: fields.join(', '),
      });
    }
  }
  return out;
}

async function budgetUse(env: Env, now: Date): Promise<Finding[]> {
  const days = [utcDay(now), utcDay(new Date(now.getTime() - DAY))];
  const res = await env.DB_CONTROL.prepare(
    'SELECT day, d1_writes, emails_sent FROM budget WHERE day IN (?1, ?2) ORDER BY day',
  )
    .bind(days[0], days[1])
    .all<{ day: string; d1_writes: number; emails_sent: number }>();
  const out: Finding[] = [];
  for (const r of res.results) {
    if (r.d1_writes > 0.8 * D1_DAILY_WRITE_LIMIT) {
      out.push({
        kind: 'budget',
        subject: `D1 writes ${r.day}`,
        detail: `${r.d1_writes} of ${D1_DAILY_WRITE_LIMIT}`,
      });
    }
    if (r.emails_sent > 0.8 * EMAIL_DAILY_CAP) {
      out.push({
        kind: 'budget',
        subject: `emails ${r.day}`,
        detail: `${r.emails_sent} of ${EMAIL_DAILY_CAP}`,
      });
    }
  }
  return out;
}

async function failedRuns(env: Env, now: Date): Promise<Finding[]> {
  const since = new Date(now.getTime() - DAY).toISOString();
  const res = await env.DB_CONTROL.prepare(
    `SELECT source_id, status, error, started_at FROM runs
     WHERE COALESCE(finished_at, started_at) >= ?1 AND (status = 'failed' OR error IS NOT NULL)
     ORDER BY started_at LIMIT ?2`,
  )
    .bind(since, MAX_ROWS)
    .all<{ source_id: string; status: string; error: string | null; started_at: string }>();
  const bySource = new Map<string, { n: number; error: string | null }>();
  for (const r of res.results) {
    const g = bySource.get(r.source_id) ?? { n: 0, error: null };
    g.n++;
    g.error = r.error ?? g.error; // rows are oldest first, so the last error wins
    bySource.set(r.source_id, g);
  }
  return [...bySource].map(([id, g]) => ({
    kind: 'failed-runs',
    subject: id,
    detail: `${g.n} failed or errored run${g.n === 1 ? '' : 's'}, latest error: ${g.error ?? 'none'}`,
  }));
}

async function stuckJobs(env: Env, now: Date): Promise<Finding[]> {
  const since = new Date(now.getTime() - DAY).toISOString();
  const stale = new Date(now.getTime() - STALE_JOB_MS).toISOString();
  const res = await env.DB_CONTROL.prepare(
    `SELECT id, kind, source_id, status, created_at, error FROM jobs
     WHERE (status IN ('failed', 'timed_out') AND COALESCE(finished_at, created_at) >= ?1)
        OR (status IN ('queued', 'starting', 'running') AND created_at < ?2)
     ORDER BY created_at LIMIT ?3`,
  )
    .bind(since, stale, MAX_ROWS)
    .all<{
      id: string;
      kind: string;
      source_id: string | null;
      status: string;
      created_at: string;
      error: string | null;
    }>();
  return res.results.map((j) => ({
    kind: 'jobs',
    subject: j.id,
    detail: `${j.kind}${j.source_id ? ` for ${j.source_id}` : ''} is ${j.status} (created ${j.created_at})${j.error ? `: ${j.error}` : ''}`,
  }));
}

async function sendReport(env: Env, findings: Finding[], deps: WatchdogDeps): Promise<void> {
  const now = deps.now();
  const { subject, text } = formatReport(findings, now);
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.kind] = (counts[f.kind] ?? 0) + 1;

  const { OPS_EMAIL: mailer, OPS_EMAIL_TO: to, OPS_EMAIL_FROM: from } = env;
  if (!mailer || !to || !from || !ADDRESS.test(to) || !ADDRESS.test(from)) {
    deps.log('watchdog report: email skipped', { findings: findings.length, counts });
    return;
  }
  const domain = from.slice(from.indexOf('@') + 1);
  const raw = buildRawEmail({ from, to, subject, text, date: now, messageId: `<${deps.newId()}@${domain}>` });
  await mailer.send(new EmailMessage(from, to, raw));
  deps.log('watchdog report: email sent', { findings: findings.length, counts });
}
