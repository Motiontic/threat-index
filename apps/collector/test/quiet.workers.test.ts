import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runStep } from '../src/step';
import { cursor, E, getRun, mkDeps, msgBody, NOW, reset, result, seedRun } from './helpers';

beforeEach(reset);

const SOURCE = 'cisa-kev';
const rec = { key: 'CVE-2024-1' } as never;

const change = (i: number) => ({
  table: 'changes' as const,
  op: 'upsert' as const,
  row: { id: `c${i}`, kind: 'public_exploit', at: NOW.toISOString(), quiet: null as string | null },
});

/** Deps whose link() returns `n` alertable change rows, and which records every row written. */
function deps(n: number, over: { more?: boolean; nextCursor?: ReturnType<typeof cursor> | null } = {}) {
  const written: { row: Record<string, unknown> }[] = [];
  const d = mkDeps({
    patternFor: () => ({
      check: async () => 'changed',
      fetch: async () =>
        result({
          more: over.more ?? false,
          ...(over.nextCursor !== undefined ? { nextCursor: over.nextCursor } : {}),
        }),
    }),
    loadParser: async () => ({ parse: () => [rec] }),
    link: async () => ({
      rows: Array.from({ length: n }, (_, i) => change(i)),
      docs: [],
      skipped: 0,
    }),
    writeRows: async (_dbs, rows) => {
      for (const r of rows) written.push(r as never);
      return { written: rows.length, statements: 1, deferred: false };
    },
  });
  return { d, written };
}
const quietOf = (w: { row: Record<string, unknown> }[]) => w.map((r) => r.row.quiet);

async function step(n: number, from = SOURCE_FROM.value, runId?: string) {
  const { d, written } = deps(n);
  const body = msgBody(SOURCE, { ...(runId ? { runId } : {}), from: from ? cursor(from) : null });
  const out = await runStep(body, 1, E, d);
  return { out, written, body };
}
const SOURCE_FROM = { value: '' };

describe('a source on its first pass', () => {
  it('a brand-new source writes first_load rows', async () => {
    const { out, written } = await step(3);
    expect(out).toEqual({ ack: true, status: 'ok' });
    expect(quietOf(written)).toEqual(['first_load', 'first_load', 'first_load']);
  });

  it('after an ok run, rows alert', async () => {
    await seedRun('r-old', SOURCE, new Date(NOW.getTime() - 3_600_000), 'ok');
    const { written } = await step(2);
    expect(quietOf(written)).toEqual([null, null]);
  });

  it('after only a step-limit ok run, the source is still on its first pass', async () => {
    await seedRun('r-old', SOURCE, new Date(NOW.getTime() - 3_600_000), 'ok', {
      error: 'step limit reached after 21 steps; continues on the next run from the saved cursor',
    });
    const { written } = await step(2);
    expect(quietOf(written)).toEqual(['first_load', 'first_load']);
  });

  it('after an unchanged run, rows alert', async () => {
    await seedRun('r-old', SOURCE, new Date(NOW.getTime() - 3_600_000), 'unchanged');
    const { written } = await step(1);
    expect(quietOf(written)).toEqual([null]);
  });

  it('a failed or running other run does not end the first pass', async () => {
    await seedRun('r-f', SOURCE, new Date(NOW.getTime() - 7_200_000), 'failed');
    await seedRun('r-r', SOURCE, new Date(NOW.getTime() - 3_600_000), 'running');
    const { written } = await step(1);
    expect(quietOf(written)).toEqual(['first_load']);
  });

  it('a complete first-load or big-file job ends it; a failed one does not', async () => {
    const job = (id: string, kind: string, status: string) =>
      E.DB_CONTROL.prepare(
        'INSERT INTO jobs (id, kind, source_id, status, created_at) VALUES (?1,?2,?3,?4,?5)',
      )
        .bind(id, kind, SOURCE, status, NOW.toISOString())
        .run();
    await job('j1', 'first-load', 'failed');
    expect(quietOf((await step(1)).written)).toEqual(['first_load']);
    await job('j2', 'big-file', 'complete');
    expect(quietOf((await step(1, 't1')).written)).toEqual([null]); // the first step moved the cursor
  });

  it('a source that never returns a cursor finishes its first pass after one ok run', async () => {
    const run = async () => {
      const { d, written } = deps(1, { nextCursor: null });
      const out = await runStep(msgBody(SOURCE), 1, E, d);
      expect(out).toEqual({ ack: true, status: 'ok' });
      return quietOf(written);
    };
    expect(await run()).toEqual(['first_load']);
    expect(await run()).toEqual([null]);
  });

  it('other sources do not count', async () => {
    await seedRun('r-other', 'epss', new Date(NOW.getTime() - 3_600_000), 'ok');
    expect(quietOf((await step(1)).written)).toEqual(['first_load']);
  });
});

describe('hold above 2,000 per run', () => {
  it('two steps of 1,500: step 2 holds 1,000, logs changes.held, runs.alerts ends at 2,000', async () => {
    await seedRun('r-old', SOURCE, new Date(NOW.getTime() - 3_600_000), 'ok'); // not a first pass
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const runId = msgBody(SOURCE).runId;
      const first = deps(1500, { more: true, nextCursor: cursor('t1') });
      await runStep(msgBody(SOURCE, { runId }), 1, E, first.d);
      expect(first.written.filter((r) => r.row.quiet === 'held')).toHaveLength(0);
      expect((await runAlerts(runId)) ?? 0).toBe(1500);

      const second = deps(1500);
      await runStep(msgBody(SOURCE, { runId, step: 1, from: cursor('t1') }), 1, E, second.d);
      expect(second.written.filter((r) => r.row.quiet === 'held')).toHaveLength(1000);
      expect(second.written.filter((r) => r.row.quiet === null)).toHaveLength(500);
      expect(await runAlerts(runId)).toBe(2000);
      const lines = log.mock.calls.map((c) => String(c[0]));
      expect(lines).toContain(
        `{"event":"changes.held","sourceId":"${SOURCE}","runId":"${runId}","held":1000}`,
      );
      expect(lines.some((l) => l.includes('"event":"changes.quiet"') && l.includes('"held":1000'))).toBe(
        true,
      );
    } finally {
      log.mockRestore();
    }
  });

  it('a redelivered step does not count twice', async () => {
    await seedRun('r-old', SOURCE, new Date(NOW.getTime() - 3_600_000), 'ok');
    const runId = msgBody(SOURCE).runId;
    const body = msgBody(SOURCE, { runId });
    const first = deps(100, { more: true, nextCursor: cursor('t1') });
    await runStep(body, 1, E, first.d);
    const again = deps(100, { more: true, nextCursor: cursor('t1') });
    const out = await runStep(body, 1, E, again.d);
    expect(out.ack).toBe(true);
    expect(await runAlerts(runId)).toBe(100);
  });

  it('first-load rows are not alertable, so they do not count toward the hold', async () => {
    const { body } = await step(2500);
    expect(await runAlerts(body.runId)).toBe(0);
  });
});

async function runAlerts(id: string): Promise<number | null> {
  const r = (await getRun(id)) as unknown as { alerts: number } | null;
  return r?.alerts ?? null;
}
