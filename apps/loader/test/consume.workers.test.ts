import { env } from 'cloudflare:workers';
import { inboxChunkKey, type LoadMessage } from '@ti/core/inbox';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { consume, type Env } from '../src/consume';

interface GlobImportMeta {
  glob(pattern: string, options: { query: string; import: string; eager: true }): Record<string, string>;
}
const sample = Object.values(
  (import.meta as unknown as GlobImportMeta).glob('./fixtures/sample-chunk.ndjson', {
    query: '?raw',
    import: 'default',
    eager: true,
  }),
)[0] as string;

const today = () => new Date().toISOString().slice(0, 10);

async function gz(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const stream = new Blob([bytes as unknown as ArrayBuffer])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const JOB = 'job1';
const KEY = inboxChunkKey(JOB, 0);
const body = (over: Partial<LoadMessage> = {}): LoadMessage => ({
  jobId: JOB,
  chunkKey: KEY,
  rows: 11,
  priority: 'steady',
  ...over,
});

function msg(b: unknown, attempts = 1) {
  const m = { body: b, attempts, ack: vi.fn(), retry: vi.fn() };
  return m;
}
async function run(b: unknown, opts: { attempts?: number; env?: Partial<Env> } = {}) {
  const sent: { body: unknown; opts: unknown }[] = [];
  const m = msg(b, opts.attempts);
  const e = {
    DB_CONTROL: env.DB_CONTROL,
    DB_VULNS: env.DB_VULNS,
    DB_ADVISORIES: env.DB_ADVISORIES,
    DB_SIGNALS: env.DB_SIGNALS,
    DB_WORLD: env.DB_WORLD,
    BUCKET: env.BUCKET,
    LOAD: { send: async (body: unknown, o: unknown) => void sent.push({ body, opts: o }) },
    ...opts.env,
  } as unknown as Env;
  await consume({ queue: 'ti-load-staging', messages: [m] } as unknown as MessageBatch<LoadMessage>, e);
  return { m, sent };
}

const TABLES: [D1Database, string][] = [
  [env.DB_VULNS, 'vulns'],
  [env.DB_ADVISORIES, 'advisories'],
  [env.DB_SIGNALS, 'signals'],
  [env.DB_SIGNALS, 'changes'],
  [env.DB_WORLD, 'techniques'],
  [env.DB_WORLD, 'vuln_techniques'],
  [env.DB_WORLD, 'companies'],
  [env.DB_WORLD, 'breach_notices'],
  [env.DB_WORLD, 'breach_events'],
  [env.DB_WORLD, 'incidents'],
];
const counts = async () =>
  Object.fromEntries(
    await Promise.all(
      TABLES.map(async ([db, t]) => [
        t,
        (await db.prepare(`SELECT count(*) AS n FROM ${t}`).first<{ n: number }>())?.n,
      ]),
    ),
  );
const total = async () => Object.values(await counts()).reduce((a, b) => (a as number) + (b as number), 0);
const meter = async () =>
  (
    await env.DB_CONTROL.prepare('SELECT d1_writes AS n FROM budget WHERE day = ?1')
      .bind(today())
      .first<{ n: number }>()
  )?.n;
const job = () =>
  env.DB_CONTROL.prepare('SELECT * FROM jobs WHERE id = ?1').bind(JOB).first<Record<string, string>>();
const put = (key: string, data: Uint8Array | string) => env.BUCKET.put(key, data);

const logs: string[] = [];
beforeEach(async () => {
  logs.length = 0;
  vi.spyOn(console, 'log').mockImplementation((s: string) => void logs.push(s));
  for (const [db, t] of TABLES) await db.prepare(`DELETE FROM ${t}`).run();
  await env.DB_CONTROL.prepare('DELETE FROM budget').run();
  await env.DB_CONTROL.prepare('DELETE FROM jobs').run();
  await env.DB_CONTROL.prepare(
    "INSERT INTO jobs (id, kind, status, created_at) VALUES (?1, 'steady', 'running', '2026-11-23T00:00:00Z')",
  )
    .bind(JOB)
    .run();
  for (const o of (await env.BUCKET.list()).objects) await env.BUCKET.delete(o.key);
});
afterEach(() => vi.restoreAllMocks());

const events = () => logs.map((l) => JSON.parse(l) as { event: string });
const hasEvent = (e: string) => events().some((x) => x.event === e);
const exists = async (key: string) => (await env.BUCKET.head(key)) !== null;

describe('loading', () => {
  it('writes every inbox table, deletes the chunk, counts the budget and acks', async () => {
    await env.DB_ADVISORIES.prepare(
      "INSERT INTO advisories (source, source_id, modified) VALUES ('nvd', 'CVE-2026-0000', '2026-01-01')",
    ).run();
    await put(KEY, await gz(sample));
    const { m, sent } = await run(body());
    expect(m.ack).toHaveBeenCalledOnce();
    expect(m.retry).not.toHaveBeenCalled();
    expect(sent).toEqual([]);
    expect(await counts()).toEqual({
      vulns: 1,
      advisories: 1, // the upsert added one, the delete removed the one inserted above
      signals: 1,
      changes: 1,
      techniques: 1,
      vuln_techniques: 1,
      companies: 1,
      breach_notices: 1,
      breach_events: 1,
      incidents: 1,
    });
    expect(await exists(KEY)).toBe(false);
    expect(await meter()).toBe(15);
    expect(hasEvent('load_ok')).toBe(true);
    expect(logs.join('\n')).not.toContain('Sample flaw'); // never row contents
  });

  it('steady goes through above the first-load cap', async () => {
    await env.DB_CONTROL.prepare('INSERT INTO budget (day, d1_writes) VALUES (?1, 90000)')
      .bind(today())
      .run();
    await put(KEY, await gz(sample));
    const { m } = await run(body());
    expect(m.ack).toHaveBeenCalledOnce();
    expect((await counts()).vulns).toBe(1);
    expect(await meter()).toBe(90_015);
  });

  it('a missing chunk (already loaded and deleted) is acked', async () => {
    const { m } = await run(body());
    expect(m.ack).toHaveBeenCalledOnce();
    expect(m.retry).not.toHaveBeenCalled();
    expect(hasEvent('load_missing')).toBe(true);
    expect(await total()).toBe(0);
    expect(await meter()).toBeUndefined();
  });

  it('a failed chunk delete retries, and redelivery rewrites the same rows and deletes', async () => {
    await put(KEY, await gz(sample));
    const failing = {
      get: (k: string) => env.BUCKET.get(k),
      delete: async () => {
        throw new Error('r2 unavailable');
      },
    } as unknown as R2Bucket;
    const first = await run(body(), { env: { BUCKET: failing } });
    expect(first.m.ack).not.toHaveBeenCalled();
    expect(first.m.retry).toHaveBeenCalledWith({ delaySeconds: 30 });
    expect(hasEvent('load_retry')).toBe(true);
    const afterFirst = await counts();
    expect(await exists(KEY)).toBe(true);

    const second = await run(body(), { attempts: 2 });
    expect(second.m.ack).toHaveBeenCalledOnce();
    expect(await counts()).toEqual(afterFirst); // identical rows, no duplicates
    expect(await exists(KEY)).toBe(false);
  });
});

describe('deferral', () => {
  it('a first-load chunk over the cap is re-sent with a delay, kept, and acked', async () => {
    await env.DB_CONTROL.prepare('INSERT INTO budget (day, d1_writes) VALUES (?1, 89999)')
      .bind(today())
      .run();
    await put(KEY, await gz(sample));
    const b = body({ priority: 'first-load' });
    const { m, sent } = await run(b);
    expect(m.ack).toHaveBeenCalledOnce();
    expect(m.retry).not.toHaveBeenCalled();
    expect(sent.length).toBe(1);
    expect(sent[0]?.body).toEqual(b);
    const delay = (sent[0]?.opts as { delaySeconds: number } | undefined)?.delaySeconds ?? 0;
    expect(delay).toBeGreaterThan(0);
    expect(delay).toBeLessThanOrEqual(86_400);
    expect(await exists(KEY)).toBe(true);
    expect(await total()).toBe(0);
    expect(await meter()).toBe(89_999);
    expect(hasEvent('load_deferred')).toBe(true);
  });

  it('a first-load chunk under the cap loads', async () => {
    await put(KEY, await gz(sample));
    const { m, sent } = await run(body({ priority: 'first-load' }));
    expect(m.ack).toHaveBeenCalledOnce();
    expect(sent).toEqual([]);
    expect(await meter()).toBe(15);
    expect(await exists(KEY)).toBe(false);
  });
});

describe('bad message bodies', () => {
  const cases: [string, unknown][] = [
    ['null', null],
    ['a string', 'inbox/job1/0.ndjson.gz'],
    ['jobId with a slash', body({ jobId: 'a/../job1' })],
    ['empty jobId', body({ jobId: '' })],
    ['jobId too long', body({ jobId: 'a'.repeat(65), chunkKey: inboxChunkKey('a'.repeat(65), 0) })],
    ['chunkKey for another job', body({ chunkKey: inboxChunkKey('other', 0) })],
    ['chunkKey walking out of the prefix', body({ chunkKey: 'inbox/job1/../other/0.ndjson.gz' })],
    ['chunkKey with a leading zero', body({ chunkKey: 'inbox/job1/00.ndjson.gz' })],
    ['chunkKey for a manifest', body({ chunkKey: 'inbox/job1/manifest.json' })],
    ['negative chunk number', body({ chunkKey: 'inbox/job1/-1.ndjson.gz' })],
    ['rows 0', body({ rows: 0 })],
    ['rows 501', body({ rows: 501 })],
    ['rows 1.5', body({ rows: 1.5 })],
    ['rows as a string', body({ rows: '5' as unknown as number })],
    ['bad priority', body({ priority: 'urgent' as never })],
  ];
  it.each(cases)('acks %s without touching R2', async (_name, b) => {
    await put('inbox/other/0.ndjson.gz', 'keep me');
    await put(KEY, await gz(sample));
    const calls: string[] = [];
    const track =
      <A extends unknown[], R>(name: string, f: (...a: A) => R) =>
      (...a: A): R => {
        calls.push(name);
        return f(...a);
      };
    const spy = {
      get: track('get', (k: string) => env.BUCKET.get(k)),
      head: track('head', (k: string) => env.BUCKET.head(k)),
      delete: track('delete', (k: string) => env.BUCKET.delete(k)),
      list: track('list', () => env.BUCKET.list()),
    } as unknown as R2Bucket;
    const { m } = await run(b, { env: { BUCKET: spy } });
    expect(m.ack).toHaveBeenCalledOnce();
    expect(m.retry).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    expect(hasEvent('load_bad_message')).toBe(true);
    expect(await exists('inbox/other/0.ndjson.gz')).toBe(true);
    expect(await exists(KEY)).toBe(true);
  });
});

describe('corrupt chunks', () => {
  async function expectFailed(data: Uint8Array | string, reasonRe: RegExp, b = body()) {
    await put(b.chunkKey, data);
    await put('inbox/other/0.ndjson.gz', 'keep me');
    const { m, sent } = await run(b);
    expect(m.ack).toHaveBeenCalledOnce();
    expect(m.retry).not.toHaveBeenCalled();
    expect(sent).toEqual([]);
    expect(await exists(b.chunkKey)).toBe(true); // kept for inspection
    expect(await exists('inbox/other/0.ndjson.gz')).toBe(true);
    expect(await total()).toBe(0);
    const j = await job();
    expect(j?.status).toBe('failed');
    expect(j?.error).toMatch(reasonRe);
    expect(j?.error?.startsWith(`${b.chunkKey}: `)).toBe(true);
    expect(j?.finished_at).toBeTruthy();
    expect(hasEvent('load_failed')).toBe(true);
  }

  it('plain text is not gzip', () => expectFailed('not gzip at all', /not valid gzip/));
  it('a line that is not JSON names the line', async () =>
    expectFailed(await gz(`${sample.split('\n')[0]}\nnope\n`), /line 2: not JSON/, body({ rows: 2 })));
  it('a line that is not { table, op, row }', async () =>
    expectFailed(
      await gz('{"table":"vulns","op":"upsert"}\n'),
      /line 1: not \{ table, op, row \}/,
      body({ rows: 1 }),
    ));
  it('a line count other than rows', async () =>
    expectFailed(await gz(sample), /11 lines, but the message says 12/, body({ rows: 12 })));
  it('more lines than rows', async () =>
    expectFailed(await gz(sample), /more than 3 lines/, body({ rows: 3 })));
  it('a table outside INBOX_TABLES (sources, jobs, budget, users)', async () => {
    for (const table of ['sources', 'cursors', 'runs', 'jobs', 'budget', 'users']) {
      await env.DB_CONTROL.prepare("UPDATE jobs SET status = 'running', error = NULL WHERE id = ?1")
        .bind(JOB)
        .run();
      await expectFailed(
        await gz(`${JSON.stringify({ table, op: 'upsert', row: { id: 'x' } })}\n`),
        /line 1: table not allowed/,
        body({ rows: 1 }),
      );
    }
    expect(
      (await env.DB_CONTROL.prepare("SELECT status FROM jobs WHERE id = 'job1'").first<{ status: string }>())
        ?.status,
    ).toBe('failed');
    expect(await env.DB_CONTROL.prepare('SELECT count(*) AS n FROM sources').first()).toEqual({ n: 0 });
  });
  it('bad UTF-8 names the line', async () =>
    expectFailed(await gz(new Uint8Array([0xff, 0xfe, 0x0a])), /line 1: not valid UTF-8/, body({ rows: 1 })));
  it('over 4 MiB stored', async () => {
    const big = new Uint8Array(4 * 1024 * 1024 + 1);
    for (let i = 0; i < big.length; i += 65_536)
      crypto.getRandomValues(big.subarray(i, Math.min(i + 65_536, big.length)));
    await expectFailed(big, /bytes stored/);
  });
  it('over 16 MiB unzipped', async () =>
    expectFailed(await gz(new Uint8Array(17 * 1024 * 1024)), /bytes unzipped/));
  it('a row that fails validation (names row, table and column, no value)', async () => {
    const line = JSON.stringify({
      table: 'vulns',
      op: 'upsert',
      row: { key: 'k', kind: 'cve', title: 't', modified: 'm', cvss: 'SECRET' },
    });
    await expectFailed(await gz(`${line}\n`), /row 0 \(vulns\.cvss\)/, body({ rows: 1 }));
    expect((await job())?.error).not.toContain('SECRET');
  });
  it('a D1 constraint failure (CHECK on signals.kind) is not retried', async () => {
    const line = JSON.stringify({
      table: 'signals',
      op: 'upsert',
      row: { vuln_key: 'a', kind: 'bogus', source: 's', ref: 'r', first_seen: 't' },
    });
    await expectFailed(await gz(`${line}\n`), /constraint failed/, body({ rows: 1 }));
  });
  it('a corrupt first-load chunk gives back nothing it never took', async () => {
    const line = JSON.stringify({
      table: 'signals',
      op: 'upsert',
      row: { vuln_key: 'a', kind: 'bogus', source: 's', ref: 'r', first_seen: 't' },
    });
    await expectFailed(await gz(`${line}\n`), /constraint failed/, body({ rows: 1, priority: 'first-load' }));
    expect(await meter()).toBe(1); // only recordLoadFailure's own steady write
  });
  it('with no job row the failure is acked and logged', async () => {
    await env.DB_CONTROL.prepare('DELETE FROM jobs').run();
    await put(KEY, 'junk');
    const { m } = await run(body());
    expect(m.ack).toHaveBeenCalledOnce();
    expect(hasEvent('load_failed')).toBe(true);
    expect(await job()).toBeNull();
  });
  it('keeps the first failure reason and truncates it to 500 characters', async () => {
    await put(KEY, 'junk');
    await run(body());
    const first = (await job())?.error;
    await put(KEY, 'other junk');
    await run(body());
    expect((await job())?.error).toBe(first);
    expect((first ?? '').length).toBeLessThanOrEqual(500);
  });
});

describe('transient errors', () => {
  const broken = {
    prepare: () => ({ bind: () => ({}) }),
    batch: async () => {
      throw new Error('D1 is unavailable');
    },
  } as unknown as D1Database;

  it('retries with a backoff and keeps the chunk', async () => {
    await put(KEY, await gz(sample));
    for (const [attempts, delaySeconds] of [
      [1, 30],
      [2, 60],
      [4, 240],
      [9, 3600],
    ] as const) {
      const { m } = await run(body(), { attempts, env: { DB_VULNS: broken } });
      expect(m.ack).not.toHaveBeenCalled();
      expect(m.retry).toHaveBeenCalledWith({ delaySeconds });
    }
    expect(await exists(KEY)).toBe(true);
    expect((await job())?.status).toBe('running');
    expect(hasEvent('load_retry')).toBe(true);
  });

  it('on the last delivery records the failure first, because the message is then gone', async () => {
    await put(KEY, await gz(sample));
    const { m } = await run(body(), { attempts: 11, env: { DB_VULNS: broken } });
    expect(m.retry).not.toHaveBeenCalled();
    expect(m.ack).toHaveBeenCalledOnce();
    const j = await job();
    expect(j?.status).toBe('failed');
    expect(j?.error).toMatch(/gave up after 11 tries/);
    expect(await exists(KEY)).toBe(true);
  });

  it('an R2 body that errors partway is retried, not marked corrupt', async () => {
    const data = await gz(sample);
    const failing = {
      get: async () => ({
        size: data.byteLength,
        body: new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(data.subarray(0, 10));
          },
          pull(c) {
            c.error(new Error('R2 connection reset'));
          },
        }),
      }),
    } as unknown as R2Bucket;
    const { m } = await run(body(), { env: { BUCKET: failing } });
    expect(m.ack).not.toHaveBeenCalled();
    expect(m.retry).toHaveBeenCalledWith({ delaySeconds: 30 });
    expect((await job())?.status).toBe('running');
    expect(hasEvent('load_retry')).toBe(true);
    expect(hasEvent('load_failed')).toBe(false);
  });

  it('a constraint error from the budget statements is retried, not corrupt', async () => {
    await put(KEY, await gz(sample));
    const control = {
      prepare: () => {
        throw new Error('CHECK constraint failed: budget');
      },
    } as unknown as D1Database;
    const { m } = await run(body(), { env: { DB_CONTROL: control } });
    expect(m.ack).not.toHaveBeenCalled();
    expect(m.retry).toHaveBeenCalledWith({ delaySeconds: 30 });
    expect(hasEvent('load_failed')).toBe(false);
    expect(await exists(KEY)).toBe(true);
  });

  it('on the last delivery, if the failure cannot be recorded, it is still logged', async () => {
    await put(KEY, await gz(sample));
    const control = {
      prepare: () => {
        throw new Error('control down');
      },
    } as unknown as D1Database;
    // Transient error: DB_VULNS is down, and so is the control DB.
    const { m } = await run(body(), { attempts: 11, env: { DB_VULNS: broken, DB_CONTROL: control } });
    expect(m.retry).not.toHaveBeenCalled();
    expect(m.ack).toHaveBeenCalledOnce();
    const failed = logs.map((l) => JSON.parse(l)).find((x) => x.event === 'load_failed');
    expect(failed.chunkKey).toBe(KEY);
    expect(failed.reason).toMatch(/gave up after 11 tries/);
    expect(failed.recordError).toMatch(/control down/);
  });

  it('on the last delivery of a corrupt chunk, an unrecordable failure is still logged', async () => {
    await put(KEY, 'junk');
    const control = {
      prepare: () => {
        throw new Error('control down');
      },
    } as unknown as D1Database;
    const { m } = await run(body(), { attempts: 11, env: { DB_CONTROL: control } });
    expect(m.retry).not.toHaveBeenCalled();
    expect(m.ack).toHaveBeenCalledOnce();
    const failed = logs.map((l) => JSON.parse(l)).find((x) => x.event === 'load_failed');
    expect(failed.chunkKey).toBe(KEY);
    expect(failed.reason).toMatch(/not valid gzip/);
  });

  it('a first-load retry gives its reservation back', async () => {
    await put(KEY, await gz(sample));
    await run(body({ priority: 'first-load' }), { env: { DB_VULNS: broken } });
    expect(await meter()).toBe(0);
  });
});
