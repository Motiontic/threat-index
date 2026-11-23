import { jobPrefix } from '@ti/core/r2-keys';
import { deriveJobKey } from '@ti/core/sign';
import type { Context } from 'hono';
import { Hono } from 'hono';
import { requireUser } from '../lib/auth';
import {
  DEEP_QUERY_STALE_MS,
  DEEP_QUERY_TIMEOUT_MS,
  DEEP_RATE_PER_HOUR,
  type DeepQueryResult,
  type DeepQueryStatus,
  deepOwner,
  HOUR_MS,
  MAX_ACTIVE_DEEP,
  MAX_DEEP_BODY_BYTES,
  MAX_RESULT_BYTES,
  publicError,
} from '../lib/deep-query';
import { validateDeepQuery } from '../lib/deep-templates';
import {
  describeE2bError,
  ENABLED_JOB_KINDS,
  type JobLauncher,
  launcherFromEnv,
  MAX_ACTIVE_JOBS,
  newJobId,
  parseApiBase,
} from '../lib/e2b';
import type { AppEnv, Bindings } from '../lib/env';
import { allow, limited } from '../lib/rate-limit';
import { searchCredits } from '../lib/search-credits';
import { JOB_ID } from './internal-jobs';

export interface DeepQueryDeps {
  launcher?: (env: Bindings) => JobLauncher | null;
  now?: () => Date;
  newId?: () => string;
}

type Ctx = Context<AppEnv>;
interface Row {
  id: string;
  kind: string;
  source_id: string | null;
  status: string;
  sandbox_id: string | null;
  created_at: string;
  finished_at: string | null;
  error: string | null;
}

const ACTIVE_DEEP = `('starting','running')`;
const ACTIVE_ALL = `('queued','starting','running')`;

/** Logs ids, template, status and sandbox only: never the user id or the params. */
function log(
  msg: string,
  f: { jobId: string; template?: string; status?: string; sandboxId?: string | null },
) {
  console.log(JSON.stringify({ msg, ...f }));
}

export function createDeepQueryRoute(deps: DeepQueryDeps = {}) {
  const route = new Hono<AppEnv>();
  const launcherFor = deps.launcher ?? launcherFromEnv;
  const now = deps.now ?? (() => new Date());

  function defer(c: Ctx, p: Promise<unknown>) {
    const safe = p.catch(() => {});
    try {
      c.executionCtx.waitUntil(safe);
    } catch {
      /* no execution context: the promise runs on its own */
    }
  }

  function killLater(c: Ctx, sandboxId: string | null, jobId: string) {
    if (!sandboxId) return;
    const launcher = launcherFor(c.env);
    if (!launcher) return;
    defer(
      c,
      launcher.kill(sandboxId).catch((err) => {
        console.log(
          JSON.stringify({
            msg: 'sandbox kill failed',
            jobId,
            kind: 'deep-query',
            sandboxId,
            error: describeE2bError(err, [c.env.E2B_API_KEY, c.env.JOB_HMAC_SECRET]),
          }),
        );
      }),
    );
  }

  /** Marks this owner's stale active rows `timed_out` and kills their sandboxes after the response. */
  async function sweep(c: Ctx, owner: string) {
    const stale = await c.env.DB_CONTROL.prepare(
      `UPDATE jobs SET status='timed_out', finished_at=?1, error='timed out'
       WHERE kind='deep-query' AND source_id=?2 AND status IN ${ACTIVE_DEEP} AND created_at < ?3
       RETURNING id, sandbox_id`,
    )
      .bind(now().toISOString(), owner, new Date(now().getTime() - DEEP_QUERY_STALE_MS).toISOString())
      .all<{ id: string; sandbox_id: string | null }>();
    for (const s of stale.results) {
      log('deep query timed out', { jobId: s.id, status: 'timed_out', sandboxId: s.sandbox_id });
      killLater(c, s.sandbox_id, s.id);
    }
  }

  async function readBody(c: Ctx): Promise<string | Response> {
    const len = c.req.header('content-length');
    if (len !== undefined && Number(len) > MAX_DEEP_BODY_BYTES)
      return c.json({ error: 'body_too_large' }, 413);
    const text = await c.req.text();
    if (new TextEncoder().encode(text).length > MAX_DEEP_BODY_BYTES)
      return c.json({ error: 'body_too_large' }, 413);
    return text;
  }

  route.post('/v1/deep-query', requireUser, async (c) => {
    c.header('cache-control', 'no-store');
    const secret = c.env.JOB_HMAC_SECRET;
    if (!secret) return c.json({ error: 'e2b_not_configured' }, 503);
    if (!(await allow(c.env.RL_DEEP, `u:${c.get('userId')}`))) return limited(c);
    const text = await readBody(c);
    if (text instanceof Response) return text;
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return c.json({ error: 'invalid_body' }, 400);
    }
    const checked = validateDeepQuery(data, now());
    if (!checked.ok) return c.json({ error: 'invalid_query', field: checked.field }, 400);
    const { query } = checked;

    if (!ENABLED_JOB_KINDS.includes('deep-query')) return c.json({ error: 'job_kind_not_ready' }, 501);
    const launcher = launcherFor(c.env);
    const apiBase = parseApiBase(c.env.API_BASE);
    if (!launcher || !apiBase) return c.json({ error: 'e2b_not_configured' }, 503);

    const owner = await deepOwner(secret, c.get('userId'));
    const db = c.env.DB_CONTROL;
    await sweep(c, owner);

    const id = (deps.newId ?? (() => newJobId(now())))();
    const nowIso = now().toISOString();
    const hourAgo = new Date(now().getTime() - HOUR_MS).toISOString();
    const ins = await db
      .prepare(
        `INSERT INTO jobs (id, kind, source_id, status, created_at)
         SELECT ?1, 'deep-query', ?2, 'starting', ?3
         WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE kind='deep-query' AND source_id=?2 AND status IN ${ACTIVE_DEEP})
           AND (SELECT COUNT(*) FROM jobs WHERE kind='deep-query' AND source_id=?2 AND created_at > ?4) < ?5
           AND (SELECT COUNT(*) FROM jobs WHERE kind='deep-query' AND status IN ${ACTIVE_DEEP}) < ?6
           AND (SELECT COUNT(*) FROM jobs WHERE status IN ${ACTIVE_ALL}) < ?7`,
      )
      .bind(id, owner, nowIso, hourAgo, DEEP_RATE_PER_HOUR, MAX_ACTIVE_DEEP, MAX_ACTIVE_JOBS)
      .run();
    if (ins.meta.changes === 0) {
      const active = await db
        .prepare(
          `SELECT id FROM jobs WHERE kind='deep-query' AND source_id=?1 AND status IN ${ACTIVE_DEEP} LIMIT 1`,
        )
        .bind(owner)
        .first<{ id: string }>();
      if (active) return c.json({ error: 'query_running', id: active.id }, 409);
      const recent = await db
        .prepare(
          `SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM jobs WHERE kind='deep-query' AND source_id=?1 AND created_at > ?2`,
        )
        .bind(owner, hourAgo)
        .first<{ n: number; oldest: string | null }>();
      if (recent && recent.n >= DEEP_RATE_PER_HOUR && recent.oldest) {
        const wait = Math.ceil((Date.parse(recent.oldest) + HOUR_MS - now().getTime()) / 1000);
        return c.json({ error: 'rate_limited' }, 429, { 'retry-after': String(Math.max(1, wait)) });
      }
      return c.json({ error: 'busy' }, 503);
    }

    const failRow = async (sandboxId: string | undefined, why: string) => {
      await db
        .prepare(
          `UPDATE jobs SET status='failed', finished_at=?2, error=?3 WHERE id=?1 AND status IN ${ACTIVE_DEEP}`,
        )
        .bind(id, now().toISOString(), `deep-query: query_failed (${why})`.slice(0, 200))
        .run();
      log('deep query launch failed', { jobId: id, template: query.template, status: 'failed', sandboxId });
      killLater(c, sandboxId ?? null, id);
      return c.json({ error: 'launch_failed' }, 502);
    };

    try {
      await c.env.BUCKET.put(
        `${jobPrefix(id)}request.json`,
        JSON.stringify({ kind: 'deep-query', ...query, createdAt: nowIso }),
      );
    } catch {
      return failRow(undefined, 'request not stored');
    }

    let sandboxId: string | undefined;
    try {
      const sandbox = await launcher.create({
        timeoutMs: DEEP_QUERY_TIMEOUT_MS,
        metadata: { jobId: id, kind: 'deep-query' },
      });
      sandboxId = sandbox.sandboxId;
      const up = await db
        .prepare(`UPDATE jobs SET status='running', sandbox_id=?2 WHERE id=?1 AND status='starting'`)
        .bind(id, sandboxId)
        .run();
      if (up.meta.changes === 0) return failRow(sandboxId, 'no longer starting');
      await sandbox.start({
        id,
        kind: 'deep-query',
        apiBase,
        hmac: await deriveJobKey(secret, id),
      });
    } catch (err) {
      return failRow(sandboxId, describeE2bError(err, [c.env.E2B_API_KEY, secret]));
    }
    log('deep query started', { jobId: id, template: query.template, status: 'running', sandboxId });
    return c.json({ id, status: 'running' }, 202);
  });

  route.get('/v1/deep-query/:id', requireUser, async (c) => {
    c.header('cache-control', 'no-store');
    const secret = c.env.JOB_HMAC_SECRET;
    if (!secret) return c.json({ error: 'e2b_not_configured' }, 503);
    const id = c.req.param('id');
    const notFound = () => c.json({ error: 'not_found' }, 404);
    if (!JOB_ID.test(id)) return notFound();
    const owner = await deepOwner(secret, c.get('userId'));
    await sweep(c, owner);
    const row = await c.env.DB_CONTROL.prepare('SELECT * FROM jobs WHERE id = ?1').bind(id).first<Row>();
    if (row?.kind !== 'deep-query' || row.source_id !== owner) return notFound();

    const req = await c.env.BUCKET.get(`${jobPrefix(id)}request.json`);
    let stored: unknown;
    try {
      stored = req ? JSON.parse(await req.text()) : null;
    } catch {
      stored = null;
    }
    const checked = validateDeepQuery(
      stored && typeof stored === 'object'
        ? {
            template: (stored as Record<string, unknown>).template,
            params: (stored as Record<string, unknown>).params,
          }
        : null,
      new Date('9999-01-01T00:00:00Z'),
    );
    if (!checked.ok) return notFound();
    const { template, params } = checked.query;

    const base = { id, template, params, createdAt: row.created_at, finishedAt: row.finished_at };
    const out = (s: Omit<DeepQueryStatus, keyof typeof base>): Response =>
      c.json({ ...base, ...s } satisfies DeepQueryStatus);

    if (row.status === 'timed_out') return out({ status: 'failed', error: 'timed_out' });
    if (row.status === 'failed') return out({ status: 'failed', error: publicError(row.error) });
    if (row.status !== 'complete') return out({ status: 'running' });

    const missing = () => out({ status: 'failed', error: 'result_missing' });
    const obj = await c.env.BUCKET.get(`${jobPrefix(id)}result.json`);
    if (!obj || obj.size > MAX_RESULT_BYTES) return missing();
    let result: DeepQueryResult;
    try {
      const parsed = JSON.parse(await obj.text()) as DeepQueryResult;
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !Array.isArray(parsed.rows) ||
        !Array.isArray(parsed.sources)
      )
        return missing();
      result = parsed;
    } catch {
      return missing();
    }
    log('deep query read', { jobId: id, template, status: 'complete', sandboxId: row.sandbox_id });
    return out({
      status: 'complete',
      result,
      credits: searchCredits([result.sources.filter((s): s is string => typeof s === 'string')]),
    });
  });

  return route;
}

export default createDeepQueryRoute();
