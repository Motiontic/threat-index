import { env } from 'cloudflare:workers';
import type { LoadMessage } from '@ti/core/inbox';
import { inboxChunkKey, inboxManifestKey } from '@ti/core/inbox';
import { deriveJobKey, SIGNATURE_HEADER, signRequest, TIMESTAMP_HEADER } from '@ti/core/sign';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import apiApp from '../src/index';
import { type ApiJobKind, JOB_TIMEOUT_MS, type JobLauncher, type SandboxJob } from '../src/lib/e2b';
import type { AppEnv, Bindings } from '../src/lib/env';
import { createInternalJobsRoute } from '../src/routes/internal-jobs';

const SECRET = env.JOB_HMAC_SECRET;
const ULID = (n: number) =>
  `01HZX3K9ABCDEFGHJKMNPQRS${String(n).padStart(2, '0').replace(/0/g, 'A').replace(/1/g, 'B')}`.slice(0, 26);
const BASE = 'https://ti-api.example.com';
const CONFIGURED = { ...env, API_BASE: BASE, E2B_TEMPLATE: 'tmpl', R2_BUCKET_NAME: 'threat-index-staging' };

interface Fake {
  launcher: JobLauncher;
  created: { timeoutMs: number; metadata: Record<string, string> }[];
  started: SandboxJob[];
  killed: string[];
  failCreate?: boolean;
  failStart?: boolean;
  failKill?: boolean;
}
function fakeLauncher(): Fake {
  let n = 0;
  const f: Fake = {
    created: [],
    started: [],
    killed: [],
    launcher: {
      async create(opts) {
        if (f.failCreate) throw new Error('create exploded e2b_secretkey123');
        f.created.push(opts);
        const sandboxId = `sbx${++n}`;
        return {
          sandboxId,
          async start(job) {
            if (f.failStart) throw new Error('start exploded');
            f.started.push(job);
          },
        };
      },
      async kill(id) {
        f.killed.push(id);
        if (f.failKill) throw new Error('kill exploded');
      },
    },
  };
  return f;
}

function recordingLoad() {
  const batches: LoadMessage[][] = [];
  let fail = false;
  const queue = {
    async send() {},
    async sendBatch(msgs: { body: LoadMessage }[]) {
      if (fail) throw new Error('queue down');
      batches.push(msgs.map((m) => m.body));
    },
  };
  return {
    queue: queue as unknown as Queue<LoadMessage>,
    batches,
    setFail: (v: boolean) => {
      fail = v;
    },
  };
}

let fake: Fake;
let load: ReturnType<typeof recordingLoad>;
let pending: Promise<unknown>[];
let clock: Date;
let ids: string[];
let enabled: readonly ApiJobKind[] | undefined;
let logs: string[];

function app(bindings: Partial<Bindings> = {}) {
  const route = createInternalJobsRoute({
    launcher: (e) => (e.E2B_API_KEY && e.E2B_TEMPLATE && e.API_BASE ? fake.launcher : null),
    now: () => clock,
    newId: () => ids.shift() ?? 'unset',
    enabledKinds: enabled,
  });
  const a = new Hono<AppEnv>().route('/', route);
  return async (req: Request) => {
    const res = await a.fetch(
      req,
      { ...CONFIGURED, LOAD: load.queue, ...bindings } as never,
      {
        waitUntil: (p: Promise<unknown>) => void pending.push(p),
        passThroughException() {},
      } as unknown as ExecutionContext,
    );
    await Promise.all(pending);
    return res;
  };
}

async function sign(key: string, method: string, path: string, body = '', ts = clock.getTime() / 1000) {
  const t = Math.floor(ts);
  return { [TIMESTAMP_HEADER]: String(t), [SIGNATURE_HEADER]: await signRequest(key, method, path, t, body) };
}
async function ops(call: ReturnType<typeof app>, method: string, path: string, payload?: unknown) {
  const body = payload === undefined ? '' : JSON.stringify(payload);
  return call(
    new Request(`https://api.test${path}`, {
      method,
      headers: { 'content-type': 'application/json', ...(await sign(SECRET, method, path, body)) },
      ...(method === 'POST' ? { body } : {}),
    }),
  );
}
async function asJob(
  call: ReturnType<typeof app>,
  id: string,
  route: string,
  payload: unknown,
  key?: string,
) {
  const path = `/internal/jobs/${id}/${route}`;
  const body = JSON.stringify(payload);
  return call(
    new Request(`https://api.test${path}`, {
      method: 'POST',
      headers: { ...(await sign(key ?? (await deriveJobKey(SECRET, id)), 'POST', path, body)) },
      body,
    }),
  );
}
const row = (id: string) =>
  env.DB_CONTROL.prepare('SELECT * FROM jobs WHERE id=?1').bind(id).first<Record<string, unknown>>();
const seed = (
  id: string,
  kind: string,
  status: string,
  source: string | null = null,
  createdAt = clock.toISOString(),
  sandbox: string | null = 'sbxS',
) =>
  env.DB_CONTROL.prepare(
    'INSERT INTO jobs (id, kind, source_id, status, sandbox_id, created_at) VALUES (?1,?2,?3,?4,?5,?6)',
  )
    .bind(id, kind, source, status, sandbox, createdAt)
    .run();
const putManifest = (id: string, chunks: unknown[], extra: object = {}) =>
  env.BUCKET.put(
    inboxManifestKey(id),
    JSON.stringify({ jobId: id, createdAt: clock.toISOString(), chunks, ...extra }),
  );
const chunks = (id: string, n: number) =>
  Array.from({ length: n }, (_, i) => ({ key: inboxChunkKey(id, i), rows: 10 }));

beforeEach(async () => {
  fake = fakeLauncher();
  load = recordingLoad();
  pending = [];
  clock = new Date('2026-11-23T12:00:00Z');
  ids = [];
  enabled = undefined;
  logs = [];
  for (const m of ['log', 'warn', 'error', 'info'] as const)
    vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));
  await env.DB_CONTROL.exec('DELETE FROM jobs; DELETE FROM cursors;');
});
afterEach(() => vi.restoreAllMocks());

describe('signatures', () => {
  const idA = ULID(1);
  const idB = ULID(2);
  it('the old routes stay closed: no header, or x-job-signature, is 401', async () => {
    const call = app();
    for (const [m, p] of [
      ['POST', '/internal/jobs'],
      ['GET', `/internal/jobs/${idA}`],
      ['POST', `/internal/jobs/${idA}/upload-urls`],
      ['POST', `/internal/jobs/${idA}/complete`],
    ] as const) {
      const res = await call(
        new Request(`https://api.test${p}`, { method: m, ...(m === 'POST' ? { body: '{}' } : {}) }),
      );
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: 'invalid_signature' });
      const old = await call(
        new Request(`https://api.test${p}`, { method: m, headers: { 'x-job-signature': 'abc' } }),
      );
      expect(old.status).toBe(401);
    }
  });
  it('rejects stale, changed-body and wrong-key calls', async () => {
    await seed(idA, 'echo', 'running');
    await seed(idB, 'echo', 'running');
    const call = app();
    const path = `/internal/jobs/${idA}/complete`;
    const body = JSON.stringify({ ok: true });
    const keyA = await deriveJobKey(SECRET, idA);
    const post = (headers: Record<string, string>, b = body) =>
      call(new Request(`https://api.test${path}`, { method: 'POST', headers, body: b }));
    expect((await post(await sign(keyA, 'POST', path, body, clock.getTime() / 1000 - 400))).status).toBe(401);
    expect((await post(await sign(keyA, 'POST', path, body), '{"ok":false,"error":"x"}')).status).toBe(401);
    // ops secret on a job route; job A's key on job B; a job key on start and status
    expect((await post(await sign(SECRET, 'POST', path, body))).status).toBe(401);
    expect((await asJob(call, idB, 'complete', { ok: true }, keyA)).status).toBe(401);
    expect((await ops(call, 'GET', `/internal/jobs/${idA}`)).status).toBe(200);
    const jobKeyOnStatus = await call(
      new Request(`https://api.test/internal/jobs/${idA}`, {
        headers: await sign(keyA, 'GET', `/internal/jobs/${idA}`),
      }),
    );
    expect(jobKeyOnStatus.status).toBe(401);
    const startBody = JSON.stringify({ kind: 'echo', reason: 'x' });
    const jobKeyOnStart = await call(
      new Request('https://api.test/internal/jobs', {
        method: 'POST',
        headers: await sign(keyA, 'POST', '/internal/jobs', startBody),
        body: startBody,
      }),
    );
    expect(jobKeyOnStart.status).toBe(401);
    // a signature bound to another method/path is refused too
    const otherPath = await sign(keyA, 'POST', `/internal/jobs/${idA}/upload-urls`, body);
    expect((await post(otherPath)).status).toBe(401);
    expect((await row(idA))?.status).toBe('running');
  });
  it('fails closed when JOB_HMAC_SECRET is unset', async () => {
    const call = app({ JOB_HMAC_SECRET: '' });
    const body = JSON.stringify({ kind: 'echo', reason: 'x' });
    const forged = await sign('x', 'POST', '/internal/jobs', body);
    const res = await call(
      new Request('https://api.test/internal/jobs', { method: 'POST', headers: forged, body }),
    );
    expect(res.status).toBe(401);
    const res2 = await asJob(call, ULID(1), 'complete', { ok: true }, 'anything');
    expect(res2.status).toBe(401);
  });
  it('413 for a body over 16 KiB, before the signature is checked', async () => {
    const call = app();
    const big = 'x'.repeat(16 * 1024 + 1);
    const res = await call(new Request('https://api.test/internal/jobs', { method: 'POST', body: big }));
    expect(res.status).toBe(413);
    const lied = await call(
      new Request('https://api.test/internal/jobs', {
        method: 'POST',
        headers: { 'content-length': '99999' },
        body: '{}',
      }),
    );
    expect(lied.status).toBe(413);
  });
  it('400 for a job id that is not a ULID, once the signature is good', async () => {
    const res = await asJob(app(), 'not-a-ulid', 'complete', { ok: true });
    expect(res.status).toBe(400);
  });
  it('the existing api test still holds: unsigned complete is 401 through the real app', async () => {
    const res = await apiApp.fetch(
      new Request('https://api.test/internal/jobs/j1/complete', { method: 'POST' }),
      env as never,
      { waitUntil() {}, passThroughException() {} } as unknown as ExecutionContext,
    );
    expect(res.status).toBe(401);
  });
});

describe('POST /internal/jobs (start)', () => {
  it('echo: 201, row running with the sandbox id, Job JSON with derived key only', async () => {
    const id = ULID(10);
    ids.push(id);
    const res = await ops(app(), 'POST', '/internal/jobs', { kind: 'echo', reason: 'hello' });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ jobId: id, status: 'running' });
    expect(await row(id)).toMatchObject({
      kind: 'echo',
      status: 'running',
      sandbox_id: 'sbx1',
      source_id: null,
    });
    expect(fake.created[0]?.timeoutMs).toBeLessThanOrEqual(50 * 60 * 1000);
    expect(fake.created[0]?.timeoutMs).toBe(JOB_TIMEOUT_MS);
    expect(fake.created[0]?.metadata).toEqual({ jobId: id, kind: 'echo' });
    const job = fake.started[0] as SandboxJob;
    expect(job).toEqual({ id, kind: 'echo', apiBase: BASE, hmac: await deriveJobKey(SECRET, id) });
    const dump = JSON.stringify([job, fake.created]);
    for (const secret of [
      SECRET,
      env.E2B_API_KEY,
      env.R2_SECRET_ACCESS_KEY,
      env.R2_ACCESS_KEY_ID,
      env.R2_ACCOUNT_ID,
    ])
      expect(dump).not.toContain(secret as string);
    expect(await (await env.BUCKET.get(`jobs/${id}/request.json`))?.json()).toMatchObject({
      kind: 'echo',
      reason: 'hello',
    });
  });
  it('big-file starts (no 501) and request.json holds `from` only when a cursor exists', async () => {
    const call = app();
    const withCursor = { requestId: ULID(21), kind: 'big-file', sourceId: 'cisa-kev', reason: 'r' };
    ids.push(ULID(21));
    await env.DB_CONTROL.prepare(
      `INSERT INTO cursors (source_id, kind, value, etag, updated_at) VALUES ('cisa-kev','timestamp','["2026-01-01T00:00:00Z","a"]','e1','2026-01-01T00:00:00Z')`,
    ).run();
    const res = await ops(call, 'POST', '/internal/jobs', withCursor);
    expect(res.status).toBe(201);
    const stored = (await (await env.BUCKET.get(`jobs/${ULID(21)}/request.json`))?.json()) as Record<
      string,
      unknown
    >;
    expect(stored.from).toEqual({ kind: 'timestamp', value: '["2026-01-01T00:00:00Z","a"]', etag: 'e1' });
    expect(stored.kind).toBe('big-file');

    await env.DB_CONTROL.exec('DELETE FROM cursors;');
    const res2 = await ops(call, 'POST', '/internal/jobs', {
      ...withCursor,
      requestId: ULID(22),
      sourceId: 'osv',
    });
    expect(res2.status).toBe(201);
    const stored2 = (await (await env.BUCKET.get(`jobs/${ULID(22)}/request.json`))?.json()) as Record<
      string,
      unknown
    >;
    expect('from' in stored2).toBe(false);
  });
  it('400 for a bad body; 501 for a kind that is not enabled', async () => {
    enabled = ['echo', 'first-load'];
    const call = app();
    expect((await ops(call, 'POST', '/internal/jobs', { kind: 'nope' })).status).toBe(400);
    expect(
      (await ops(call, 'POST', '/internal/jobs', { kind: 'echo', reason: 'x'.repeat(201) })).status,
    ).toBe(400);
    const fl = { requestId: ULID(11), kind: 'big-file', sourceId: 'cisa-kev', reason: 'r' };
    const res = await ops(call, 'POST', '/internal/jobs', fl);
    expect(res.status).toBe(501);
    expect(await res.json()).toEqual({ error: 'job_kind_not_ready' });
    expect(await row(ULID(11))).toBeNull();
    expect(fake.created).toHaveLength(0);
  });
  it('400 for a url that is not https, an id that is not a ULID or a malformed cursor', async () => {
    enabled = ['echo', 'first-load'];
    const call = app();
    const base = { requestId: ULID(12), kind: 'first-load', sourceId: 'cisa-kev', reason: 'r' };
    expect((await ops(call, 'POST', '/internal/jobs', { ...base, url: 'http://x.test/a' })).status).toBe(400);
    expect((await ops(call, 'POST', '/internal/jobs', { ...base, requestId: 'nope' })).status).toBe(400);
    expect(
      (await ops(call, 'POST', '/internal/jobs', { ...base, cursor: { kind: 'x', value: 'y' } })).status,
    ).toBe(400);
  });
  it('unknown_source 400 and source_not_ingestible 403, before any launch', async () => {
    enabled = ['echo', 'first-load'];
    const call = app();
    const mk = (n: number, sourceId: string) => ({
      requestId: ULID(n),
      kind: 'first-load',
      sourceId,
      reason: 'r',
    });
    const a = await ops(call, 'POST', '/internal/jobs', mk(13, 'no-such-source'));
    expect(a.status).toBe(400);
    expect(await a.json()).toEqual({ error: 'unknown_source' });
    const b = await ops(call, 'POST', '/internal/jobs', mk(14, 'malpedia'));
    expect(b.status).toBe(403);
    expect(await b.json()).toEqual({ error: 'source_not_ingestible' });
    expect(fake.created).toHaveLength(0);
  });
  it('503 e2b_not_configured, with no row', async () => {
    ids.push(ULID(15));
    const res = await ops(app({ E2B_API_KEY: '' }), 'POST', '/internal/jobs', { kind: 'echo', reason: 'x' });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'e2b_not_configured' });
    expect((await env.DB_CONTROL.prepare('SELECT COUNT(*) AS n FROM jobs').first<{ n: number }>())?.n).toBe(
      0,
    );
  });
  it('a 56-minute-old active row becomes timed_out and its sandbox is killed', async () => {
    const old = new Date(clock.getTime() - 56 * 60 * 1000).toISOString();
    await seed(ULID(16), 'echo', 'running', null, old, 'sbxOLD');
    ids.push(ULID(17));
    const res = await ops(app(), 'POST', '/internal/jobs', { kind: 'echo', reason: 'x' });
    expect(res.status).toBe(201);
    expect(await row(ULID(16))).toMatchObject({ status: 'timed_out' });
    expect(fake.killed).toContain('sbxOLD');
  });
  it('a running day-scoped job past JOB_TIMEOUT_MS is failed as timed out and a new one starts', async () => {
    enabled = ['echo', 'search-index'];
    const old = new Date(clock.getTime() - JOB_TIMEOUT_MS - 60_000).toISOString();
    // the hung job's own request id (the daily id is deterministic), then another day's id
    for (const [n, requestId] of [ULID(21), ULID(23)].entries()) {
      await env.DB_CONTROL.exec('DELETE FROM jobs');
      fake.killed.length = 0;
      await seed(ULID(21), 'search-index', 'running', null, old, 'sbxHUNG');
      ids.push(ULID(30 + n));
      const res = await ops(app(), 'POST', '/internal/jobs', {
        requestId,
        kind: 'search-index',
        reason: 'nightly',
      });
      expect(res.status).toBe(201);
      expect(await row(ULID(21))).toMatchObject({ status: 'failed', error: 'timed out' });
      expect(fake.killed).toContain('sbxHUNG');
      const id = ((await res.json()) as { jobId: string }).jobId;
      expect(await row(id)).toMatchObject({ status: 'running' });
    }
  });
  it('a fresh running day-scoped job still blocks a new one', async () => {
    enabled = ['echo', 'search-index'];
    const recent = new Date(clock.getTime() - JOB_TIMEOUT_MS + 60_000).toISOString();
    await seed(ULID(25), 'search-index', 'running', null, recent);
    const res = await ops(app(), 'POST', '/internal/jobs', {
      requestId: ULID(26),
      kind: 'search-index',
      reason: 'nightly',
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jobId: ULID(25), status: 'running', existing: true });
    expect(await row(ULID(25))).toMatchObject({ status: 'running' });
    expect(fake.created).toHaveLength(0);
  });
  it('the same requestId twice makes one row and one sandbox', async () => {
    enabled = ['echo', 'first-load'];
    const call = app();
    const req = { requestId: ULID(18), kind: 'first-load', sourceId: 'cisa-kev', reason: 'r' };
    expect((await ops(call, 'POST', '/internal/jobs', req)).status).toBe(201);
    const again = await ops(call, 'POST', '/internal/jobs', req);
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ jobId: ULID(18), status: 'running', existing: true });
    expect(fake.created).toHaveLength(1);
    // replay after the job ended is also a no-op
    await env.DB_CONTROL.exec(`UPDATE jobs SET status='complete' WHERE id='${ULID(18)}'`);
    const late = await ops(call, 'POST', '/internal/jobs', req);
    expect(await late.json()).toEqual({ jobId: ULID(18), status: 'complete', existing: true });
    expect(fake.created).toHaveLength(1);
  });
  it('an active job of the same kind and source is returned as existing', async () => {
    enabled = ['echo', 'first-load'];
    await seed(ULID(19), 'first-load', 'running', 'cisa-kev');
    const res = await ops(app(), 'POST', '/internal/jobs', {
      requestId: ULID(20),
      kind: 'first-load',
      sourceId: 'cisa-kev',
      reason: 'r',
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jobId: ULID(19), status: 'running', existing: true });
    expect(await row(ULID(20))).toBeNull();
  });
  it('429 too_many_jobs at MAX_ACTIVE_JOBS', async () => {
    enabled = ['echo', 'first-load'];
    for (let i = 0; i < 5; i++) await seed(ULID(30 + i), 'echo', 'running', `src${i}`);
    const res = await ops(app(), 'POST', '/internal/jobs', {
      requestId: ULID(21),
      kind: 'first-load',
      sourceId: 'cisa-kev',
      reason: 'r',
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: 'too_many_jobs' });
    expect(fake.created).toHaveLength(0);
  });
  it('502 launch_failed when create throws: row failed, no key in the error', async () => {
    fake.failCreate = true;
    const id = ULID(22);
    ids.push(id);
    const res = await ops(app(), 'POST', '/internal/jobs', { kind: 'echo', reason: 'x' });
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: 'launch_failed', jobId: id });
    const r = await row(id);
    expect(r?.status).toBe('failed');
    expect(String(r?.error)).not.toContain('e2b_secretkey123');
  });
  it('502 when start throws: the sandbox that exists is killed', async () => {
    fake.failStart = true;
    const id = ULID(23);
    ids.push(id);
    const res = await ops(app(), 'POST', '/internal/jobs', { kind: 'echo', reason: 'x' });
    expect(res.status).toBe(502);
    expect(await row(id)).toMatchObject({ status: 'failed', sandbox_id: 'sbx1' });
    expect(fake.killed).toEqual(['sbx1']);
  });
});

describe('GET /internal/jobs/:id (status)', () => {
  it('200 with the row, 404 for an unknown job', async () => {
    await seed(ULID(40), 'echo', 'running');
    const ok = await ops(app(), 'GET', `/internal/jobs/${ULID(40)}`);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({
      jobId: ULID(40),
      kind: 'echo',
      sourceId: null,
      status: 'running',
      sandboxId: 'sbxS',
      createdAt: clock.toISOString(),
      finishedAt: null,
      manifestKey: null,
      error: null,
    });
    expect((await ops(app(), 'GET', `/internal/jobs/${ULID(41)}`)).status).toBe(404);
  });
});

describe('upload-urls', () => {
  const id = ULID(50);
  it('200 in request order, with the presigned URL host and a signature', async () => {
    await seed(id, 'echo', 'running');
    const keys = [`jobs/${id}/echo.json`, inboxManifestKey(id)];
    const res = await asJob(app(), id, 'upload-urls', { keys });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { expiresInSeconds: number; urls: { key: string; url: string }[] };
    expect(body.expiresInSeconds).toBe(600);
    expect(body.urls.map((u) => u.key)).toEqual(keys);
    const u = new URL(body.urls[0]?.url as string);
    expect(u.host).toBe(`${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`);
    expect(u.pathname).toBe(`/threat-index-staging/jobs/${id}/echo.json`);
    expect(u.searchParams.get('X-Amz-Signature')).toBeTruthy();
    expect(logs.join('\n')).not.toContain('X-Amz-Signature');
  });
  it('400 invalid_key with no URLs at all when one key is bad', async () => {
    await seed(id, 'echo', 'running');
    const res = await asJob(app(), id, 'upload-urls', { keys: [`jobs/${id}/ok`, 'raw/evil'] });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'invalid_key', key: 'raw/evil' });
  });
  it('400 for 0 or 51 keys; 404 unknown; 409 not running; 503 no signing config', async () => {
    const call = app();
    expect((await asJob(call, id, 'upload-urls', { keys: [] })).status).toBe(400);
    expect(
      (
        await asJob(call, id, 'upload-urls', {
          keys: Array.from({ length: 51 }, (_, i) => `jobs/${id}/${i}`),
        })
      ).status,
    ).toBe(400);
    expect((await asJob(call, id, 'upload-urls', { keys: [`jobs/${id}/a`] })).status).toBe(404);
    await seed(id, 'echo', 'starting');
    const nr = await asJob(call, id, 'upload-urls', { keys: [`jobs/${id}/a`] });
    expect(nr.status).toBe(409);
    expect(await nr.json()).toEqual({ error: 'job_not_running' });
    await env.DB_CONTROL.exec(`UPDATE jobs SET status='running' WHERE id='${id}'`);
    const res = await asJob(app({ R2_SECRET_ACCESS_KEY: '' }), id, 'upload-urls', { keys: [`jobs/${id}/a`] });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'r2_not_configured' });
  });
});

describe('complete', () => {
  const id = ULID(60);
  it('ok:true with an empty manifest completes, sends nothing, kills the sandbox', async () => {
    await seed(id, 'echo', 'running');
    await putManifest(id, []);
    const res = await asJob(app(), id, 'complete', { ok: true });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jobId: id, status: 'complete', queued: 0 });
    expect(await row(id)).toMatchObject({ status: 'complete', manifest_key: inboxManifestKey(id) });
    expect(load.batches).toHaveLength(0);
    expect(fake.killed).toEqual(['sbxS']);
  });
  it('250 chunks go out as 100, 100, 50 in manifest order', async () => {
    await seed(id, 'echo', 'running');
    await putManifest(id, chunks(id, 250));
    const res = await asJob(app(), id, 'complete', { ok: true });
    expect(await res.json()).toEqual({ jobId: id, status: 'complete', queued: 250 });
    expect(load.batches.map((b) => b.length)).toEqual([100, 100, 50]);
    expect(load.batches.flat().map((m) => m.chunkKey)).toEqual(chunks(id, 250).map((c) => c.key));
  });
  it('a repeated complete is 200 repeated and sends nothing', async () => {
    await seed(id, 'echo', 'running');
    await putManifest(id, chunks(id, 3));
    const call = app();
    await asJob(call, id, 'complete', { ok: true });
    const sent = load.batches.length;
    const killed = fake.killed.length;
    const again = await asJob(call, id, 'complete', { ok: true });
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ jobId: id, status: 'complete', queued: 0, repeated: true });
    expect(load.batches).toHaveLength(sent);
    expect(fake.killed).toHaveLength(killed);
  });
  it('404 unknown; 409 for queued, starting and timed_out', async () => {
    const call = app();
    expect((await asJob(call, id, 'complete', { ok: true })).status).toBe(404);
    for (const [i, status] of ['queued', 'starting', 'timed_out'].entries()) {
      const jid = ULID(70 + i);
      await seed(jid, 'echo', status);
      const res = await asJob(call, jid, 'complete', { ok: true });
      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: 'job_not_running' });
    }
  });
  it('ok:false marks failed (error cut to 1000), reads no manifest, kills the sandbox', async () => {
    await seed(id, 'echo', 'running');
    const get = vi.spyOn(env.BUCKET, 'get');
    const res = await asJob(app(), id, 'complete', { ok: false, error: 'e'.repeat(2000) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ jobId: id, status: 'failed', queued: 0 });
    expect(String((await row(id))?.error)).toHaveLength(1000);
    expect(get).not.toHaveBeenCalled();
    expect(fake.killed).toEqual(['sbxS']);
    const again = await asJob(app(), id, 'complete', { ok: false, error: 'x' });
    expect(await again.json()).toMatchObject({ repeated: true, status: 'failed' });
  });
  it.each([
    ['missing', undefined, 'manifest missing'],
    ['bad JSON', '{', 'not JSON'],
    ['other jobId', JSON.stringify({ jobId: 'x', createdAt: 'z', chunks: [] }), 'jobId'],
    [
      'wrong key',
      JSON.stringify({ jobId: id, createdAt: 'z', chunks: [{ key: 'inbox/x', rows: 1 }] }),
      'bad key',
    ],
  ])('an invalid manifest (%s) fails the job with 400 and sends nothing', async (_n, text, reason) => {
    await seed(id, 'echo', 'running');
    if (text !== undefined) await env.BUCKET.put(inboxManifestKey(id), text);
    else await env.BUCKET.delete(inboxManifestKey(id));
    const res = await asJob(app(), id, 'complete', { ok: true });
    expect(res.status).toBe(400);
    const r = await row(id);
    expect(r?.status).toBe('failed');
    expect(String(r?.error)).toContain('invalid_manifest');
    expect(String(r?.error)).toContain(reason);
    expect(load.batches).toHaveLength(0);
    expect(fake.killed).toEqual(['sbxS']);
  });
  it('a failed send is 503, the job stays running and a retry succeeds', async () => {
    await seed(id, 'echo', 'running');
    await putManifest(id, chunks(id, 2));
    const call = app();
    load.setFail(true);
    const res = await asJob(call, id, 'complete', { ok: true });
    expect(res.status).toBe(503);
    expect((await row(id))?.status).toBe('running');
    expect(fake.killed).toHaveLength(0);
    load.setFail(false);
    const retry = await asJob(call, id, 'complete', { ok: true });
    expect(await retry.json()).toEqual({ jobId: id, status: 'complete', queued: 2 });
  });
  it("priority comes from the job's kind, whatever the manifest says", async () => {
    enabled = ['echo', 'first-load', 'big-file'];
    const call = app();
    for (const [n, kind, want] of [
      [80, 'first-load', 'first-load'],
      [81, 'big-file', 'steady'],
    ] as const) {
      const jid = ULID(n);
      await seed(jid, kind, 'running', kind === 'first-load' ? 'cisa-kev' : 'epss');
      await putManifest(
        jid,
        chunks(jid, 3).map((c) => ({ ...c, priority: kind === 'first-load' ? 'steady' : 'first-load' })),
      );
      await asJob(call, jid, 'complete', { ok: true });
      const msgs = load.batches.flat().filter((m) => m.jobId === jid);
      expect(msgs).toHaveLength(3);
      expect(msgs.every((m) => m.priority === want)).toBe(true);
    }
  });
  it('the cursor reaches cursors only after a successful complete, never after ok:false', async () => {
    enabled = ['echo', 'first-load'];
    const call = app();
    const cursor = { kind: 'timestamp', value: '2026-11-23T00:00:00Z', etag: 'e1' };
    const a = ULID(90);
    const b = ULID(91);
    // start through the route so request.json carries the cursor
    for (const [rid, source] of [
      [a, 'cisa-kev'],
      [b, 'epss'],
    ] as const)
      await ops(call, 'POST', '/internal/jobs', {
        requestId: rid,
        kind: 'first-load',
        sourceId: source,
        reason: 'r',
        cursor,
      });
    expect((await row(a))?.status).toBe('running');
    const count = async () =>
      (await env.DB_CONTROL.prepare('SELECT COUNT(*) AS n FROM cursors').first<{ n: number }>())?.n;
    expect(await count()).toBe(0);
    await asJob(call, b, 'complete', { ok: false, error: 'boom' });
    expect(await count()).toBe(0);
    await putManifest(a, chunks(a, 1));
    load.setFail(true);
    await asJob(call, a, 'complete', { ok: true });
    expect(await count()).toBe(0); // send failed: cursor not moved
    load.setFail(false);
    await asJob(call, a, 'complete', { ok: true });
    expect(
      await env.DB_CONTROL.prepare('SELECT * FROM cursors WHERE source_id=?1').bind('cisa-kev').first(),
    ).toMatchObject({
      kind: 'timestamp',
      value: '2026-11-23T00:00:00Z',
      etag: 'e1',
      updated_at: clock.toISOString(),
    });
    expect(await count()).toBe(1);
  });
  it('a failed kill is logged, without the sandbox key', async () => {
    await seed(id, 'echo', 'running');
    await putManifest(id, []);
    fake.failKill = true;
    const res = await asJob(app(), id, 'complete', { ok: true });
    expect(res.status).toBe(200);
    expect(logs.join('\n')).toContain('sandbox kill failed');
  });
});

describe('round trip with the test acting as the sandbox', () => {
  it('start → upload-urls → complete → status, using only the captured Job JSON', async () => {
    const call = app();
    const id = ULID(95);
    ids.push(id);
    expect((await ops(call, 'POST', '/internal/jobs', { kind: 'echo', reason: 'rt' })).status).toBe(201);
    const job = fake.started[0] as SandboxJob;
    // The sandbox signs with job.hmac only.
    const echoKey = `jobs/${job.id}/echo.json`;
    const urls = await asJob(
      call,
      job.id,
      'upload-urls',
      { keys: [echoKey, inboxManifestKey(job.id)] },
      job.hmac,
    );
    expect(urls.status).toBe(200);
    // R2 is not reachable from the test: put the objects as the PUT would.
    await env.BUCKET.put(echoKey, JSON.stringify({ id: job.id, kind: 'echo' }));
    await putManifest(job.id, []);
    const done = await asJob(call, job.id, 'complete', { ok: true }, job.hmac);
    expect(await done.json()).toEqual({ jobId: id, status: 'complete', queued: 0 });
    const status = await ops(call, 'GET', `/internal/jobs/${id}`);
    expect(await status.json()).toMatchObject({
      status: 'complete',
      sandboxId: 'sbx1',
      manifestKey: inboxManifestKey(id),
    });
    expect(fake.killed).toEqual(['sbx1']);
  });
});

describe('logs', () => {
  it('hold no presigned URL, key or secret across a full flow', async () => {
    const call = app();
    const id = ULID(96);
    ids.push(id);
    await ops(call, 'POST', '/internal/jobs', { kind: 'echo', reason: 'rt' });
    const job = fake.started[0] as SandboxJob;
    await asJob(call, id, 'upload-urls', { keys: [`jobs/${id}/a`] }, job.hmac);
    await putManifest(id, []);
    await asJob(call, id, 'complete', { ok: true }, job.hmac);
    const all = logs.join('\n');
    for (const bad of [
      'X-Amz-Signature',
      SECRET,
      job.hmac,
      env.E2B_API_KEY,
      env.R2_SECRET_ACCESS_KEY,
      env.R2_ACCESS_KEY_ID,
    ])
      expect(all).not.toContain(bad as string);
  });
});
