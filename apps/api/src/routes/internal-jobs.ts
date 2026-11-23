import type { LoadMessage } from '@ti/core/inbox';
import { inboxManifestKey } from '@ti/core/inbox';
import type { JobRequest } from '@ti/core/control';
import { canIngest } from '@ti/core/licence';
import { jobPrefix } from '@ti/core/r2-keys';
import { deriveJobKey, SIGNATURE_HEADER, TIMESTAMP_HEADER, verifyRequest } from '@ti/core/sign';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import type { Context } from 'hono';
import { Hono } from 'hono';
import { z } from 'zod';
import {
  type ApiJobKind,
  describeE2bError,
  ENABLED_JOB_KINDS,
  JOB_TIMEOUT_MS,
  type JobLauncher,
  launcherFromEnv,
  MAX_ACTIVE_JOBS,
  newJobId,
  parseApiBase,
  parseManifest,
  STALE_AFTER_MS,
} from '../lib/e2b';
import type { AppEnv, Bindings } from '../lib/env';
import {
  allowedPrefixes,
  MAX_UPLOAD_URLS,
  presignPut,
  r2SigningConfig,
  UPLOAD_URL_TTL_SECONDS,
  uploadKeyError,
} from '../lib/presign';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_ERROR_CHARS = 1000;
const SEND_BATCH = 100;
const ACTIVE = `('queued','starting','running')`;
export const JOB_ID = /^[0-9A-HJKMNP-TV-Z]{26}(-[0-9]{1,5})?$/;

const cursorSchema = z.object({
  kind: z.enum(['commit', 'timestamp', 'etag', 'version']),
  value: z.string().max(2048),
  etag: z.string().max(2048).optional(),
});
const jobRequestSchema = z.object({
  requestId: z.string().regex(JOB_ID),
  kind: z.enum(['first-load', 'epss-diff', 'big-file']),
  sourceId: z.string().min(1).max(100),
  reason: z.string().max(200),
  url: z
    .string()
    .max(2048)
    .refine((u) => {
      try {
        return new URL(u).protocol === 'https:';
      } catch {
        return false;
      }
    })
    .optional(),
  cursor: cursorSchema.optional(),
}) satisfies z.ZodType<JobRequest>;
const echoSchema = z.object({ kind: z.literal('echo'), reason: z.string().max(200) });
const startSchema = z.union([jobRequestSchema, echoSchema]);
const uploadSchema = z.object({ keys: z.array(z.string()).min(1).max(MAX_UPLOAD_URLS) });
const completeSchema = z.union([
  z.object({ ok: z.literal(true) }),
  z.object({ ok: z.literal(false), error: z.string() }),
]);

interface JobRow {
  id: string;
  kind: ApiJobKind;
  source_id: string | null;
  status: string;
  sandbox_id: string | null;
  created_at: string;
  finished_at: string | null;
  manifest_key: string | null;
  error: string | null;
}

export interface InternalJobsDeps {
  launcher?: (env: Bindings) => JobLauncher | null;
  now?: () => Date;
  newId?: () => string;
  enabledKinds?: readonly ApiJobKind[];
}

type Ctx = Context<AppEnv>;

function log(msg: string, fields: { jobId: string; kind?: string; status?: string; sandboxId?: string | null }) {
  console.log(JSON.stringify({ msg, ...fields }));
}

export function createInternalJobsRoute(deps: InternalJobsDeps = {}) {
  const route = new Hono<AppEnv>();
  const launcherFor = deps.launcher ?? launcherFromEnv;
  const now = deps.now ?? (() => new Date());
  const enabled = deps.enabledKinds ?? ENABLED_JOB_KINDS;

  /** Runs `p` after the response. Falls back to a floating promise when there is no execution context. */
  function defer(c: Ctx, p: Promise<unknown>) {
    const safe = p.catch(() => {});
    try {
      c.executionCtx.waitUntil(safe);
    } catch {
      /* no execution context: the promise runs on its own */
    }
  }

  function killLater(c: Ctx, sandboxId: string | null | undefined, jobId: string, kind?: string) {
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
            kind,
            sandboxId,
            error: describeE2bError(err, [c.env.E2B_API_KEY]),
          }),
        );
      }),
    );
  }

  /** Reads the body (≤ 16 KiB). Returns a Response when it is too big. */
  async function readBody(c: Ctx): Promise<string | Response> {
    const len = c.req.header('content-length');
    if (len !== undefined && Number(len) > MAX_BODY_BYTES) return c.json({ error: 'body_too_large' }, 413);
    const text = await c.req.text();
    if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return c.json({ error: 'body_too_large' }, 413);
    return text;
  }

  async function signed(c: Ctx, key: string | undefined, body: string): Promise<boolean> {
    return verifyRequest(key, {
      method: c.req.method,
      path: new URL(c.req.url).pathname,
      timestamp: c.req.header(TIMESTAMP_HEADER) ?? null,
      signature: c.req.header(SIGNATURE_HEADER) ?? null,
      body,
    });
  }

  /** Ops/collector key: size check, then signature. Returns the body text or a Response. */
  async function opsAuth(c: Ctx): Promise<string | Response> {
    const body = await readBody(c);
    if (body instanceof Response) return body;
    if (!(await signed(c, c.env.JOB_HMAC_SECRET || undefined, body))) return c.json({ error: 'invalid_signature' }, 401);
    return body;
  }

  /** Sandbox key for `:id`: size check, signature, then the id shape. */
  async function jobAuth(c: Ctx): Promise<{ id: string; body: string } | Response> {
    const body = await readBody(c);
    if (body instanceof Response) return body;
    const secret = c.env.JOB_HMAC_SECRET;
    const id = c.req.param('id') ?? '';
    const key = secret ? await deriveJobKey(secret, id) : undefined;
    if (!(await signed(c, key, body))) return c.json({ error: 'invalid_signature' }, 401);
    if (!JOB_ID.test(id)) return c.json({ error: 'invalid_job_id' }, 400);
    return { id, body };
  }

  function parseJson<T extends z.ZodType>(c: Ctx, schema: T, text: string): z.infer<T> | Response {
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return c.json({ error: 'invalid_body' }, 400);
    }
    const r = schema.safeParse(data);
    return r.success ? r.data : c.json({ error: 'invalid_body' }, 400);
  }

  const getRow = (c: Ctx, id: string) =>
    c.env.DB_CONTROL.prepare('SELECT * FROM jobs WHERE id = ?1').bind(id).first<JobRow>();

  async function failJob(c: Ctx, id: string, error: string): Promise<void> {
    await c.env.DB_CONTROL.prepare(
      `UPDATE jobs SET status='failed', finished_at=?2, error=?3 WHERE id=?1 AND status IN ('starting','running')`,
    )
      .bind(id, now().toISOString(), error.slice(0, MAX_ERROR_CHARS))
      .run();
  }

  // ---- Start ----
  route.post('/internal/jobs', async (c) => {
    const text = await opsAuth(c);
    if (text instanceof Response) return text;
    const req = parseJson(c, startSchema, text);
    if (req instanceof Response) return req;

    if (!enabled.includes(req.kind)) return c.json({ error: 'job_kind_not_ready' }, 501);
    let sourceId: string | null = null;
    if (req.kind !== 'echo') {
      const source = SOURCE_BY_ID.get(req.sourceId);
      if (!source) return c.json({ error: 'unknown_source' }, 400);
      if (!canIngest(source.licence)) return c.json({ error: 'source_not_ingestible' }, 403);
      sourceId = req.sourceId;
    }
    const launcher = launcherFor(c.env);
    const apiBase = parseApiBase(c.env.API_BASE);
    if (!launcher || !apiBase) return c.json({ error: 'e2b_not_configured' }, 503);

    const db = c.env.DB_CONTROL;
    const stale = await db
      .prepare(
        `UPDATE jobs SET status='timed_out', finished_at=?1, error='timed out' WHERE status IN ${ACTIVE} AND created_at < ?2 RETURNING id, kind, sandbox_id`,
      )
      .bind(now().toISOString(), new Date(now().getTime() - STALE_AFTER_MS).toISOString())
      .all<{ id: string; kind: string; sandbox_id: string | null }>();
    for (const s of stale.results) {
      log('job timed out', { jobId: s.id, kind: s.kind, status: 'timed_out', sandboxId: s.sandbox_id });
      killLater(c, s.sandbox_id, s.id, s.kind);
    }

    const id = req.kind === 'echo' ? (deps.newId ?? (() => newJobId(now())))() : req.requestId;
    const existing = (row: Pick<JobRow, 'id' | 'status'>) =>
      c.json({ jobId: row.id, status: row.status, existing: true }, 200);

    const same = await getRow(c, id);
    if (same) return existing(same);
    const ins = await db
      .prepare(
        `INSERT INTO jobs (id, kind, source_id, status, created_at)
         SELECT ?1, ?2, ?3, 'starting', ?4
         WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE kind = ?2 AND source_id IS ?3 AND status IN ${ACTIVE})
           AND (SELECT COUNT(*) FROM jobs WHERE status IN ${ACTIVE}) < ?5`,
      )
      .bind(id, req.kind, sourceId, now().toISOString(), MAX_ACTIVE_JOBS)
      .run();
    if (ins.meta.changes === 0) {
      const again = await getRow(c, id);
      if (again) return existing(again);
      const active = await db
        .prepare(`SELECT id, status FROM jobs WHERE kind = ?1 AND source_id IS ?2 AND status IN ${ACTIVE} LIMIT 1`)
        .bind(req.kind, sourceId)
        .first<{ id: string; status: string }>();
      if (active) return existing(active);
      return c.json({ error: 'too_many_jobs' }, 429);
    }

    const fail = async (error: string, sandboxId?: string) => {
      await failJob(c, id, error);
      log('job launch failed', { jobId: id, kind: req.kind, status: 'failed', sandboxId });
      killLater(c, sandboxId, id, req.kind);
      return c.json({ error: 'launch_failed', jobId: id }, 502);
    };

    try {
      const { kind: _k, ...rest } = req as JobRequest & { kind: ApiJobKind };
      await c.env.BUCKET.put(`${jobPrefix(id)}request.json`, JSON.stringify({ kind: req.kind, ...rest }));
    } catch {
      return fail('could not store the request');
    }

    let sandboxId: string | undefined;
    try {
      const sandbox = await launcher.create({ timeoutMs: JOB_TIMEOUT_MS, metadata: { jobId: id, kind: req.kind } });
      sandboxId = sandbox.sandboxId;
      const up = await db
        .prepare(`UPDATE jobs SET status='running', sandbox_id=?2 WHERE id=?1 AND status='starting'`)
        .bind(id, sandboxId)
        .run();
      if (up.meta.changes === 0) return fail('job no longer starting', sandboxId);
      await sandbox.start({
        id,
        kind: req.kind,
        ...(sourceId ? { sourceId } : {}),
        ...(req.kind !== 'echo' && req.url ? { url: req.url } : {}),
        apiBase,
        hmac: await deriveJobKey(c.env.JOB_HMAC_SECRET, id),
      });
    } catch (err) {
      return fail(describeE2bError(err, [c.env.E2B_API_KEY, c.env.JOB_HMAC_SECRET]), sandboxId);
    }
    log('job started', { jobId: id, kind: req.kind, status: 'running', sandboxId });
    return c.json({ jobId: id, status: 'running' }, 201);
  });

  // ---- Status ----
  route.get('/internal/jobs/:id', async (c) => {
    const body = await opsAuth(c);
    if (body instanceof Response) return body;
    const id = c.req.param('id');
    if (!JOB_ID.test(id)) return c.json({ error: 'invalid_job_id' }, 400);
    const row = await getRow(c, id);
    if (!row) return c.json({ error: 'not_found' }, 404);
    return c.json({
      jobId: row.id,
      kind: row.kind,
      sourceId: row.source_id,
      status: row.status,
      sandboxId: row.sandbox_id,
      createdAt: row.created_at,
      finishedAt: row.finished_at,
      manifestKey: row.manifest_key,
      error: row.error,
    });
  });

  // ---- Upload URLs ----
  route.post('/internal/jobs/:id/upload-urls', async (c) => {
    const auth = await jobAuth(c);
    if (auth instanceof Response) return auth;
    const body = parseJson(c, uploadSchema, auth.body);
    if (body instanceof Response) return body;
    const row = await getRow(c, auth.id);
    if (!row) return c.json({ error: 'not_found' }, 404);
    if (row.status !== 'running') return c.json({ error: 'job_not_running' }, 409);
    const prefixes = allowedPrefixes(row.kind, row.id);
    for (const key of body.keys) {
      if (uploadKeyError(key, prefixes) !== null) return c.json({ error: 'invalid_key', key }, 400);
    }
    const cfg = r2SigningConfig(c.env);
    if (!cfg) return c.json({ error: 'r2_not_configured' }, 503);
    const urls = await Promise.all(body.keys.map(async (key) => ({ key, url: await presignPut(cfg, key) })));
    return c.json({ expiresInSeconds: UPLOAD_URL_TTL_SECONDS, urls });
  });

  // ---- Complete ----
  route.post('/internal/jobs/:id/complete', async (c) => {
    const auth = await jobAuth(c);
    if (auth instanceof Response) return auth;
    const body = parseJson(c, completeSchema, auth.body);
    if (body instanceof Response) return body;
    const { id } = auth;
    const row = await getRow(c, id);
    if (!row) return c.json({ error: 'not_found' }, 404);
    if (row.status === 'complete' || row.status === 'failed')
      return c.json({ jobId: id, status: row.status, queued: 0, repeated: true });
    if (row.status !== 'running') return c.json({ error: 'job_not_running' }, 409);

    if (!body.ok) {
      await failJob(c, id, body.error.slice(0, MAX_ERROR_CHARS));
      log('job failed', { jobId: id, kind: row.kind, status: 'failed', sandboxId: row.sandbox_id });
      killLater(c, row.sandbox_id, id, row.kind);
      return c.json({ jobId: id, status: 'failed', queued: 0 });
    }

    const manifestKey = inboxManifestKey(id);
    const obj = await c.env.BUCKET.get(manifestKey);
    const parsed = obj ? parseManifest(await obj.text(), id, row.kind) : { error: 'manifest missing' };
    if ('error' in parsed) {
      await failJob(c, id, `invalid_manifest: ${parsed.error}`);
      log('job failed', { jobId: id, kind: row.kind, status: 'failed', sandboxId: row.sandbox_id });
      killLater(c, row.sandbox_id, id, row.kind);
      return c.json({ error: 'invalid_manifest' }, 400);
    }

    // Priority comes from the job's kind, never from the manifest.
    const priority = row.kind === 'first-load' ? 'first-load' : 'steady';
    const messages = parsed.manifest.chunks.map(
      (ch): { body: LoadMessage } => ({
        body: { jobId: id, chunkKey: ch.key, rows: ch.rows, priority },
      }),
    );
    try {
      for (let i = 0; i < messages.length; i += SEND_BATCH)
        await c.env.LOAD.sendBatch(messages.slice(i, i + SEND_BATCH));
    } catch {
      log('queue send failed', { jobId: id, kind: row.kind, status: 'running', sandboxId: row.sandbox_id });
      return c.json({ error: 'queue_unavailable' }, 503);
    }

    // The cursor moves only now, after every message is out.
    if (row.source_id) {
      const reqObj = await c.env.BUCKET.get(`${jobPrefix(id)}request.json`);
      let cursor: z.infer<typeof cursorSchema> | undefined;
      if (reqObj) {
        try {
          const r = z.object({ cursor: cursorSchema.optional() }).safeParse(JSON.parse(await reqObj.text()));
          cursor = r.success ? r.data.cursor : undefined;
        } catch {
          cursor = undefined;
        }
      }
      if (cursor) {
        await c.env.DB_CONTROL.prepare(
          `INSERT INTO cursors (source_id, kind, value, etag, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT(source_id) DO UPDATE SET kind=excluded.kind, value=excluded.value, etag=excluded.etag, updated_at=excluded.updated_at`,
        )
          .bind(row.source_id, cursor.kind, cursor.value, cursor.etag ?? null, now().toISOString())
          .run();
      }
    }

    await c.env.DB_CONTROL.prepare(
      `UPDATE jobs SET status='complete', finished_at=?2, manifest_key=?3 WHERE id=?1 AND status='running'`,
    )
      .bind(id, now().toISOString(), manifestKey)
      .run();
    log('job complete', { jobId: id, kind: row.kind, status: 'complete', sandboxId: row.sandbox_id });
    killLater(c, row.sandbox_id, id, row.kind);
    return c.json({ jobId: id, status: 'complete', queued: messages.length });
  });

  return route;
}

export default createInternalJobsRoute();
