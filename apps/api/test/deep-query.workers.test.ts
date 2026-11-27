import { env } from 'cloudflare:workers';
import { deriveJobKey } from '@ti/core/sign';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { DEEP_QUERY_STALE_MS, deepOwner } from '../src/lib/deep-query';
import type { JobLauncher, SandboxJob } from '../src/lib/e2b';
import type { AppEnv, Bindings } from '../src/lib/env';
import { createDeepQueryRoute } from '../src/routes/deep-query';

const SECRET = env.JOB_HMAC_SECRET;
const BASE = 'https://ti-api.example.com';
// RL_DEEP is off here: these tests cover the hourly limit; launch.workers.test.ts covers the per-minute one.
const CONFIGURED = { ...env, API_BASE: BASE, E2B_TEMPLATE: 'tmpl', RL_DEEP: undefined };
const ULID = (n: number) =>
  `01HZX3K9ABCDEFGHJKMNPQ${String(n)
    .padStart(4, '0')
    .replace(/[01]/g, (d) => (d === '0' ? 'A' : 'B'))}`;
const USER = 'user_abc123secret';
const KEV_QUERY = { template: 'kev-additions', params: { from: '2025-05-01', to: '2025-05-31' } };

interface Fake {
  launcher: JobLauncher;
  created: { timeoutMs: number; metadata: Record<string, string> }[];
  started: SandboxJob[];
  killed: string[];
  failCreate: boolean;
}
let fake: Fake;
let clock: Date;
let ids: string[];
let pending: Promise<unknown>[];

function fakeLauncher(): Fake {
  let n = 0;
  const f: Fake = {
    created: [],
    started: [],
    killed: [],
    failCreate: false,
    launcher: {
      async create(opts) {
        if (f.failCreate) throw new Error('create exploded e2b_secretkey123');
        f.created.push(opts);
        const sandboxId = `sbx${++n}`;
        return {
          sandboxId,
          async start(job) {
            f.started.push(job);
          },
        };
      },
      async kill(id) {
        f.killed.push(id);
      },
    },
  };
  return f;
}

const route = () =>
  createDeepQueryRoute({
    launcher: (e: Bindings) => (e.E2B_API_KEY && e.E2B_TEMPLATE && e.API_BASE ? fake.launcher : null),
    now: () => clock,
    newId: () => ids.shift() ?? 'unset',
  });

// `vi.mock('@hono/clerk-auth')` does not work in this pool: the test app sets `clerkAuth` from a header.
function makeApp() {
  const app = new Hono<AppEnv>();
  app.use('/v1/*', async (c, next) => {
    const user = c.req.header('x-test-user');
    c.set('clerkAuth' as never, (() => (user ? { userId: user } : { userId: null })) as never);
    await next();
  });
  app.route('/', route());
  return app;
}

async function call(
  method: string,
  path: string,
  opts: { user?: string | null; body?: unknown; raw?: string; bindings?: Partial<Bindings> } = {},
) {
  const headers: Record<string, string> = {};
  const user = opts.user === undefined ? USER : opts.user;
  if (user) headers['x-test-user'] = user;
  const init: RequestInit = { method, headers };
  if (opts.raw !== undefined) init.body = opts.raw;
  else if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const res = await makeApp().fetch(
    new Request(`https://api.test${path}`, init),
    { ...CONFIGURED, ...opts.bindings } as never,
    {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughException() {},
    } as unknown as ExecutionContext,
  );
  await Promise.all(pending);
  return res;
}
const post = (body: unknown, user?: string | null) => call('POST', '/v1/deep-query', { body, user });
const json = async (res: Response) => (await res.json()) as any;
const row = (id: string) =>
  env.DB_CONTROL.prepare('SELECT * FROM jobs WHERE id=?1').bind(id).first<Record<string, any>>();
const seed = async (
  id: string,
  owner: string,
  status: string,
  createdAt: Date,
  sandbox: string | null = null,
  error: string | null = null,
) => {
  await env.DB_CONTROL.prepare(
    `INSERT INTO jobs (id, kind, source_id, status, sandbox_id, created_at, error) VALUES (?1,'deep-query',?2,?3,?4,?5,?6)`,
  )
    .bind(id, owner, status, sandbox, createdAt.toISOString(), error)
    .run();
};
const putRequest = (id: string, query = KEV_QUERY) =>
  env.BUCKET.put(
    `jobs/${id}/request.json`,
    JSON.stringify({ kind: 'deep-query', ...query, createdAt: clock.toISOString() }),
  );
const minutesAgo = (m: number) => new Date(clock.getTime() - m * 60_000);

beforeEach(async () => {
  fake = fakeLauncher();
  clock = new Date('2026-11-23T12:00:00Z');
  ids = Array.from({ length: 30 }, (_, i) => ULID(i + 2));
  pending = [];
  await env.DB_CONTROL.prepare('DELETE FROM jobs').run();
  const listed = await env.BUCKET.list({ prefix: 'jobs/' });
  if (listed.objects.length > 0) await env.BUCKET.delete(listed.objects.map((o) => o.key));
});

describe('POST /v1/deep-query', () => {
  it('needs sign-in', async () => {
    expect((await post(KEV_QUERY, null)).status).toBe(401);
    expect((await call('GET', `/v1/deep-query/${ULID(2)}`, { user: null })).status).toBe(401);
  });

  it('refuses bad input', async () => {
    const bad = await post({ template: 'drop-tables', params: {} });
    expect(bad.status).toBe(400);
    expect(await json(bad)).toEqual({ error: 'invalid_query', field: 'template' });
    const extra = await post({ template: 'cve-history', params: { cve: 'CVE-2024-1234', sql: 'x' } });
    expect(await json(extra)).toEqual({ error: 'invalid_query', field: 'sql' });
    const inj = await post({ template: 'cve-history', params: { cve: "CVE-1' OR 1=1" } });
    expect(inj.status).toBe(400);
    expect(await json(inj)).toEqual({ error: 'invalid_query', field: 'cve' });
    expect((await call('POST', '/v1/deep-query', { raw: '{nope' })).status).toBe(400);
    const big = await call('POST', '/v1/deep-query', {
      raw: JSON.stringify({ template: 'company-breaches', params: { company: 'a'.repeat(3 * 1024) } }),
    });
    expect(big.status).toBe(413);
    expect(await json(big)).toEqual({ error: 'body_too_large' });
    expect(fake.created).toHaveLength(0);
    const { results } = await env.DB_CONTROL.prepare('SELECT id FROM jobs').all();
    expect(results).toHaveLength(0);
  });

  it('503s when E2B or the secret is not configured', async () => {
    const res = await call('POST', '/v1/deep-query', {
      body: KEV_QUERY,
      bindings: { E2B_TEMPLATE: undefined },
    });
    expect(res.status).toBe(503);
    expect(await json(res)).toEqual({ error: 'e2b_not_configured' });
    const noSecret = await call('POST', '/v1/deep-query', {
      body: KEV_QUERY,
      bindings: { JOB_HMAC_SECRET: '' },
    });
    expect(noSecret.status).toBe(503);
  });

  it('starts a job without putting the user id or params anywhere it should not', async () => {
    const res = await post({ template: 'kev-additions', params: { from: '2025-05-01', to: '2025-05-31' } });
    expect(res.status).toBe(202);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const id = ULID(2);
    expect(await json(res)).toEqual({ id, status: 'running' });
    const r = await row(id);
    expect(r).toMatchObject({ kind: 'deep-query', status: 'running', sandbox_id: 'sbx1' });
    expect(r?.source_id).toBe(await deepOwner(SECRET, USER));
    expect(String(r?.source_id).startsWith('dq:')).toBe(true);
    expect(JSON.stringify(r)).not.toContain(USER);
    const req = await (await env.BUCKET.get(`jobs/${id}/request.json`))?.text();
    expect(req).not.toContain(USER);
    expect(JSON.parse(req as string)).toMatchObject({ kind: 'deep-query', ...KEV_QUERY });
    expect(fake.created).toEqual([{ timeoutMs: 5 * 60 * 1000, metadata: { jobId: id, kind: 'deep-query' } }]);
    expect(fake.started).toEqual([
      { id, kind: 'deep-query', apiBase: BASE, hmac: await deriveJobKey(SECRET, id) },
    ]);
    expect(JSON.stringify(fake.started)).not.toContain('2025-05');
  });

  it('answers 409 with the running id for a second query from the same user', async () => {
    expect((await post(KEV_QUERY)).status).toBe(202);
    const again = await post(KEV_QUERY);
    expect(again.status).toBe(409);
    expect(await json(again)).toEqual({ error: 'query_running', id: ULID(2) });
    expect(fake.created).toHaveLength(1);
  });

  it('answers 429 with retry-after on the 11th query in an hour', async () => {
    const owner = await deepOwner(SECRET, USER);
    for (let i = 0; i < 10; i++) await seed(ULID(100 + i), owner, 'failed', minutesAgo(50 - i));
    const res = await post(KEV_QUERY);
    expect(res.status).toBe(429);
    expect(await json(res)).toEqual({ error: 'rate_limited' });
    expect(res.headers.get('retry-after')).toBe(String(10 * 60)); // oldest row is 50 minutes old
    expect(fake.created).toHaveLength(0);
    // a different user is not limited
    expect((await post(KEV_QUERY, 'user_other')).status).toBe(202);
  });

  it('answers 503 busy when three deep queries are active', async () => {
    for (const [i, u] of ['a', 'b', 'c'].entries())
      await seed(ULID(100 + i), `dq:${u}`, 'running', minutesAgo(1), `s${i}`);
    const res = await post(KEV_QUERY);
    expect(res.status).toBe(503);
    expect(await json(res)).toEqual({ error: 'busy' });
    expect(fake.created).toHaveLength(0);
  });

  it('answers 503 busy when MAX_ACTIVE_JOBS jobs are active', async () => {
    for (let i = 0; i < 5; i++)
      await env.DB_CONTROL.prepare(
        `INSERT INTO jobs (id, kind, source_id, status, created_at) VALUES (?1,'first-load',?2,'running',?3)`,
      )
        .bind(ULID(100 + i), `src${i}`, minutesAgo(1).toISOString())
        .run();
    expect((await post(KEV_QUERY)).status).toBe(503);
  });

  it('marks the row failed and answers 502 when the launcher throws', async () => {
    fake.failCreate = true;
    const res = await post(KEV_QUERY);
    expect(res.status).toBe(502);
    expect(await json(res)).toEqual({ error: 'launch_failed' });
    expect(await row(ULID(2))).toMatchObject({ status: 'failed' });
    expect(JSON.stringify(await row(ULID(2)))).not.toContain('e2b_secretkey123');
    const get = await call('GET', `/v1/deep-query/${ULID(2)}`);
    expect(await json(get)).toMatchObject({ status: 'failed', error: 'query_failed' });
  });

  it('sweeps a 7-minute-old running row to timed_out and kills its sandbox', async () => {
    const owner = await deepOwner(SECRET, USER);
    await seed(
      ULID(100),
      owner,
      'running',
      new Date(clock.getTime() - DEEP_QUERY_STALE_MS - 60_000),
      'sbx-old',
    );
    const res = await post(KEV_QUERY);
    expect(res.status).toBe(202);
    expect(await row(ULID(100))).toMatchObject({ status: 'timed_out' });
    expect(fake.killed).toEqual(['sbx-old']);
  });
});

describe('GET /v1/deep-query/:id', () => {
  const owner = () => deepOwner(SECRET, USER);

  it('404s for another user, a missing row, a bad id and another kind', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'running', minutesAgo(1), 's1');
    await putRequest(id);
    const other = await call('GET', `/v1/deep-query/${id}`, { user: 'user_other' });
    const missing = await call('GET', `/v1/deep-query/${ULID(3)}`);
    expect(other.status).toBe(404);
    expect(missing.status).toBe(404);
    expect(await json(other)).toEqual(await json(missing));
    expect((await call('GET', '/v1/deep-query/not-an-id')).status).toBe(404);
    await env.DB_CONTROL.prepare(
      `INSERT INTO jobs (id, kind, source_id, status, created_at) VALUES (?1,'first-load',?2,'running',?3)`,
    )
      .bind(ULID(4), await owner(), clock.toISOString())
      .run();
    expect((await call('GET', `/v1/deep-query/${ULID(4)}`)).status).toBe(404);
  });

  it('reports running', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'running', minutesAgo(1), 's1');
    await putRequest(id);
    const res = await call('GET', `/v1/deep-query/${id}`);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body = await json(res);
    expect(body).toMatchObject({
      id,
      template: 'kev-additions',
      params: KEV_QUERY.params,
      status: 'running',
      finishedAt: null,
    });
    expect(body.result).toBeUndefined();
  });

  it('returns rows and credits for a complete job', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'complete', minutesAgo(2), 's1');
    await putRequest(id);
    const result = {
      template: 'kev-additions',
      rows: [{ source: 'cisa-kev', jobId: 'J', record: { vulnKey: 'CVE-2025-3248' } }],
      rowCount: 1,
      truncated: false,
      sources: ['cisa-kev'],
      scanned: { objects: 1, bytes: 10 },
      tookMs: 5,
    };
    await env.BUCKET.put(`jobs/${id}/result.json`, JSON.stringify(result));
    const body = await json(await call('GET', `/v1/deep-query/${id}`));
    expect(body.status).toBe('complete');
    expect(body.result).toEqual(result);
    expect(body.credits).toHaveLength(1);
    expect(body.credits[0]).toMatchObject({ sourceId: 'cisa-kev' });
  });

  it('shows only a listed error code for a failed job', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'failed', minutesAgo(2), 's1', 'DuckDB crashed at /tmp/secret/path: boom');
    await putRequest(id);
    const body = await json(await call('GET', `/v1/deep-query/${id}`));
    expect(body).toMatchObject({ status: 'failed', error: 'query_failed' });
    expect(JSON.stringify(body)).not.toContain('secret');
    const id2 = ULID(3);
    await seed(id2, await owner(), 'failed', minutesAgo(2), 's1', 'deep-query: scan_too_large');
    await putRequest(id2);
    expect(await json(await call('GET', `/v1/deep-query/${id2}`))).toMatchObject({ error: 'scan_too_large' });
    const id3 = ULID(4);
    await seed(id3, await owner(), 'failed', minutesAgo(2), 's1', 'deep-query: something_else');
    await putRequest(id3);
    expect(await json(await call('GET', `/v1/deep-query/${id3}`))).toMatchObject({ error: 'query_failed' });
  });

  it('reports result_missing when a complete job has no usable result', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'complete', minutesAgo(2), 's1');
    await putRequest(id);
    expect(await json(await call('GET', `/v1/deep-query/${id}`))).toMatchObject({
      status: 'failed',
      error: 'result_missing',
    });
    await env.BUCKET.put(`jobs/${id}/result.json`, 'not json');
    expect(await json(await call('GET', `/v1/deep-query/${id}`))).toMatchObject({ error: 'result_missing' });
    await env.BUCKET.put(`jobs/${id}/result.json`, 'x'.repeat(5 * 1024 * 1024 + 1));
    expect(await json(await call('GET', `/v1/deep-query/${id}`))).toMatchObject({ error: 'result_missing' });
  });

  it('shows a timed_out row as failed/timed_out, and sweeps a stale running row', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'running', minutesAgo(7), 'sbx-old');
    await putRequest(id);
    const body = await json(await call('GET', `/v1/deep-query/${id}`));
    expect(body).toMatchObject({ status: 'failed', error: 'timed_out' });
    expect(fake.killed).toEqual(['sbx-old']);
  });
});

describe('DELETE /v1/deep-query/:id', () => {
  const owner = () => deepOwner(SECRET as string, USER);
  it('cancels the owner\'s running job, kills its sandbox, and GET then shows failed/cancelled', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'running', minutesAgo(1), 'sbx-live');
    await putRequest(id);
    const res = await call('DELETE', `/v1/deep-query/${id}`);
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({ status: 'cancelled' });
    expect(fake.killed).toEqual(['sbx-live']);
    expect(await row(id)).toMatchObject({ status: 'failed', error: 'deep-query: cancelled' });
    const got = await json(await call('GET', `/v1/deep-query/${id}`));
    expect(got).toMatchObject({ status: 'failed', error: 'cancelled' });
  });
  it('404s for another user, an unknown id and a bad id, with the same body', async () => {
    const id = ULID(2);
    await seed(id, await owner(), 'running', minutesAgo(1), 'sbx-live');
    const other = await call('DELETE', `/v1/deep-query/${id}`, { user: 'user_other' });
    const unknown = await call('DELETE', `/v1/deep-query/${ULID(9)}`);
    const bad = await call('DELETE', '/v1/deep-query/nope');
    expect([other.status, unknown.status, bad.status]).toEqual([404, 404, 404]);
    expect(await json(other)).toEqual(await json(unknown));
    expect(fake.killed).toEqual([]);
    expect((await row(id))?.status).toBe('running');
  });
  it('returns the current status of a finished job and changes nothing', async () => {
    const done = ULID(2);
    const failed = ULID(3);
    await seed(done, await owner(), 'complete', minutesAgo(5), 'sbx-a');
    await seed(failed, await owner(), 'failed', minutesAgo(5), 'sbx-b', 'deep-query: query_failed');
    expect(await json(await call('DELETE', `/v1/deep-query/${done}`))).toEqual({ status: 'complete' });
    expect(await json(await call('DELETE', `/v1/deep-query/${failed}`))).toEqual({ status: 'failed' });
    expect(fake.killed).toEqual([]);
    expect((await row(done))?.status).toBe('complete');
  });
  it('needs sign-in', async () => {
    expect((await call('DELETE', `/v1/deep-query/${ULID(2)}`, { user: null })).status).toBe(401);
  });
});
