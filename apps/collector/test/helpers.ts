import { env } from 'cloudflare:workers';
import type { Cursor } from '@ti/core/types';
import type { PatternResult } from '@ti/patterns/types';
import { ulid } from 'ulid';
import type { StepDeps } from '../src/deps';
import type { Env, JobMessage } from '../src/env';

export const E = env as unknown as Env;
export const NOW = new Date('2026-11-23T12:00:00.000Z');
export const HOUR = 3_600_000;

/** Empties the control tables, KV and R2 so each test starts clean. */
export async function reset(): Promise<void> {
  await E.DB_CONTROL.batch([
    E.DB_CONTROL.prepare('DELETE FROM runs'),
    E.DB_CONTROL.prepare('DELETE FROM cursors'),
    E.DB_CONTROL.prepare('DELETE FROM jobs'),
    E.DB_CONTROL.prepare('DELETE FROM budget'),
  ]);
  for (const { name } of (await E.SETTINGS.list()).keys) await E.SETTINGS.delete(name);
  for (const o of (await E.BUCKET.list()).objects) await E.BUCKET.delete(o.key);
}

export async function seedRun(
  id: string,
  sourceId: string,
  startedAt: Date,
  status: string,
  extra: { found?: number; error?: string | null; finishedAt?: Date } = {},
): Promise<void> {
  await E.DB_CONTROL.prepare(
    'INSERT INTO runs (id, source_id, started_at, finished_at, status, found, error) VALUES (?1,?2,?3,?4,?5,?6,?7)',
  )
    .bind(
      id,
      sourceId,
      startedAt.toISOString(),
      extra.finishedAt?.toISOString() ?? (status === 'running' ? null : startedAt.toISOString()),
      status,
      extra.found ?? 0,
      extra.error ?? null,
    )
    .run();
}

export async function seedCursor(sourceId: string, c: Cursor): Promise<void> {
  await E.DB_CONTROL.prepare(
    'INSERT OR REPLACE INTO cursors (source_id, kind, value, etag, updated_at) VALUES (?1,?2,?3,?4,?5)',
  )
    .bind(sourceId, c.kind, c.value, c.etag ?? null, NOW.toISOString())
    .run();
}

export const getRun = (id: string) =>
  E.DB_CONTROL.prepare('SELECT * FROM runs WHERE id = ?1').bind(id).first<{
    id: string;
    source_id: string;
    status: string;
    found: number;
    written: number;
    bytes: number;
    error: string | null;
    finished_at: string | null;
  }>();

export const getCursor = (sourceId: string) =>
  E.DB_CONTROL.prepare('SELECT kind, value, etag FROM cursors WHERE source_id = ?1')
    .bind(sourceId)
    .first<{ kind: string; value: string; etag: string | null }>();

export const runsByStatus = async () =>
  (
    await E.DB_CONTROL.prepare('SELECT status, COUNT(*) AS n FROM runs GROUP BY status').all<{
      status: string;
      n: number;
    }>()
  ).results;

/** A fake producer that records what is sent. */
export function fakeJobs(opts: { failSend?: boolean } = {}) {
  const sent: JobMessage[] = [];
  const queue = {
    send: async (body: JobMessage) => {
      if (opts.failSend) throw new Error('queue down');
      sent.push(body);
    },
    sendBatch: async (msgs: { body: JobMessage }[]) => {
      for (const m of msgs) sent.push(m.body);
    },
  } as unknown as Queue<JobMessage>;
  return { sent, queue };
}

export const newRunId = () => ulid(NOW.getTime());

export const cursor = (value: string, etag?: string): Cursor => ({
  kind: 'timestamp',
  value,
  ...(etag ? { etag } : {}),
});

export function msgBody(sourceId: string, over: Partial<JobMessage> = {}): JobMessage {
  return { sourceId, runId: newRunId(), step: 0, from: null, ...over };
}

export function result(over: Partial<PatternResult> = {}): PatternResult {
  return {
    items: [{ id: 'a', body: { n: 1 } }],
    receipt: {
      source: 'x',
      runId: 'r',
      fetchedAt: NOW.toISOString(),
      contentType: 'application/json',
      body: '{"raw":1}',
    },
    nextCursor: cursor('t1'),
    more: false,
    ...over,
  };
}

/** Deps made of fakes. `fetch` throws, so no test reaches the internet. */
export function mkDeps(over: Partial<StepDeps> = {}): StepDeps & { logs: string[] } {
  const logs: string[] = [];
  return {
    patternFor: () => ({ check: async () => 'changed', fetch: async () => result() }),
    loadParser: async () => ({ parse: () => [] }),
    link: async () => ({ rows: [], docs: [], skipped: 0 }),
    writeRows: async () => ({ written: 0, statements: 0, deferred: false }),
    startJob: async () => ({ jobId: 'job' }),
    fetch: (() => {
      throw new Error('network is off in tests');
    }) as unknown as typeof fetch,
    wait: async () => {},
    now: () => NOW,
    newId: () => ulid(NOW.getTime()),
    log: (msg, extra) => logs.push(JSON.stringify({ msg, ...extra })),
    ...over,
    logs,
  };
}

export async function gunzipText(obj: R2ObjectBody): Promise<string> {
  return new Response(obj.body.pipeThrough(new DecompressionStream('gzip'))).text();
}
