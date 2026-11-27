// The pure part of scripts/quiet-old-changes.mjs: rows in, updates out. No I/O, so it is unit tested.
// The rule itself (the 14-day window and what an unparseable date does) is imported from the linker, so there
// is one rule for the linker, the loaders and this backlog.
import { ageQuiet } from '../../packages/linker/src/age.ts';

/** True when this run finished its source's pass: the same test as apps/collector/src/step.ts. */
export function runCompleted(run) {
  if (run.status === 'unchanged') return true;
  return run.status === 'ok' && !String(run.error ?? '').startsWith('step limit reached');
}

/** A job that loaded the whole source: the same test as the collector's `jobs` check. */
export function jobCompleted(job) {
  return job.status === 'complete' && (job.kind === 'first-load' || job.kind === 'big-file');
}

/**
 * Where each source's first load ended.
 *  - a source with a completed run or job: `{ until }`, the finish time of the earliest one;
 *  - a source with runs but none completed: `{ all: true }`;
 *  - a source with no runs (for example one read from CVE List records): absent, so none of its rows are.
 * @param {{source_id: string, status: string, error?: string|null, finished_at?: string|null, started_at?: string|null}[]} runs
 * @param {{source_id: string|null, kind: string, status: string, finished_at?: string|null, created_at?: string|null}[]} jobs
 * @returns {Map<string, {until: string} | {all: true}>}
 */
export function firstLoadBoundaries(runs, jobs) {
  const out = new Map();
  const seenRuns = new Set();
  const ends = new Map();
  const note = (source, end) => {
    const have = ends.get(source);
    if (have === undefined || end < have) ends.set(source, end);
  };
  for (const r of runs) {
    seenRuns.add(r.source_id);
    if (runCompleted(r)) note(r.source_id, r.finished_at ?? r.started_at ?? '');
  }
  for (const j of jobs) {
    if (j.source_id && jobCompleted(j)) note(j.source_id, j.finished_at ?? j.created_at ?? '');
  }
  for (const s of seenRuns) if (!ends.has(s)) out.set(s, { all: true });
  for (const [s, until] of ends) out.set(s, { until });
  return out;
}

/** The event date of one change row, from the data the backlog reads; null when the source gives none. */
export function eventAtOf(c, ctx) {
  switch (c.kind) {
    case 'newly_exploited':
      return c.new ?? null;
    case 'public_exploit':
      return ctx.exploit.get(c.entity_key) ?? null;
    case 'fix_released':
      return ctx.fix.get(`${c.source}\u0000${c.entity_key}`) ?? null;
    case 'breach_notice':
      return ctx.notice.get(c.new ?? '') ?? null;
    default:
      return null; // new_advisory is limited to 14 days already; epss_band and cvss_change are current
  }
}

/**
 * Plans the updates for rows with `quiet IS NULL`. Rows already quiet are never passed in, and any that are
 * are skipped. An update is planned only when it changes `event_at` or `quiet`, so a second run plans none.
 * Never plans `held`.
 * @param {{id: string, kind: string, source: string|null, entity_key: string, new: string|null, at: string, event_at?: string|null, quiet?: string|null}[]} changes
 * @param {{exploit: Map<string,string>, fix: Map<string,string>, notice: Map<string,string>, boundaries: Map<string, {until: string}|{all: true}>}} ctx
 */
export function planQuiet(changes, ctx) {
  const updates = [];
  const counts = new Map();
  for (const c of changes) {
    if (c.quiet !== null && c.quiet !== undefined) continue;
    const eventAt = eventAtOf(c, ctx) ?? c.event_at ?? null;
    let quiet = ageQuiet(eventAt, c.at);
    if (quiet === null && c.source) {
      const b = ctx.boundaries.get(c.source);
      if (b && ('all' in b || c.at <= b.until)) quiet = 'first_load';
    }
    if (quiet === (c.quiet ?? null) && eventAt === (c.event_at ?? null)) continue;
    updates.push({ id: c.id, event_at: eventAt, quiet });
    if (quiet) {
      const k = `${c.kind}\t${c.source ?? ''}\t${quiet}`;
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
  }
  const summary = [...counts]
    .map(([k, n]) => {
      const [kind, source, reason] = k.split('\t');
      return { kind, source, reason, rows: n };
    })
    .sort((a, b) => b.rows - a.rows || a.kind.localeCompare(b.kind) || a.source.localeCompare(b.source));
  return { updates, summary };
}

const lit = (v) => (v === null || v === undefined ? 'NULL' : `'${String(v).replaceAll("'", "''")}'`);
const REASONS = new Set(['old', 'first_load']);

/** UPDATE statements, in chunks of at most `size`. Each guards on `quiet IS NULL`, so it never overwrites a reason. */
export function updateChunks(updates, size = 500) {
  const chunks = [];
  for (let i = 0; i < updates.length; i += size) {
    chunks.push(
      updates
        .slice(i, i + size)
        .map((u) => {
          if (u.quiet !== null && !REASONS.has(u.quiet))
            throw new Error(`refusing to write quiet=${u.quiet}`);
          return `UPDATE changes SET event_at = ${lit(u.event_at)}, quiet = ${lit(u.quiet)} WHERE id = ${lit(u.id)} AND quiet IS NULL;`;
        })
        .join('\n'),
    );
  }
  return chunks;
}
