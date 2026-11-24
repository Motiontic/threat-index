import { SOURCE_BY_ID } from '@ti/sources/registry';
import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../src/index';
import { dueSources, plan } from '../src/planner';
import { E, fakeJobs, HOUR, NOW, reset, seedCursor, seedRun } from './helpers';

const CRON = '0 */3 * * *';
const ids = async () => (await dueSources(E, CRON, NOW)).map((d) => d.source.id);

beforeEach(reset);

describe('dueSources', () => {
  it('a success 1 h ago is not due, 4 h ago is, never is', async () => {
    expect(await ids()).toContain('cve-list'); // never run
    await seedRun('r1', 'cve-list', new Date(NOW.getTime() - 1 * HOUR), 'ok');
    expect(await ids()).not.toContain('cve-list');
    await reset();
    await seedRun('r2', 'cve-list', new Date(NOW.getTime() - 4 * HOUR), 'ok');
    expect(await ids()).toContain('cve-list');
  });

  it('a 2.6 h old success is due (30 min slack for cron drift)', async () => {
    await seedRun('r1', 'cve-list', new Date(NOW.getTime() - 2.6 * HOUR), 'unchanged');
    expect(await ids()).toContain('cve-list');
  });

  it('a latest run that failed is due; a young running run is skipped; an old one is not', async () => {
    await seedRun('r1', 'cisa-kev', new Date(NOW.getTime() - 1 * HOUR), 'failed');
    expect(await ids()).toContain('cisa-kev');
    await seedRun('r2', 'osv', new Date(NOW.getTime() - 1 * HOUR), 'running');
    expect(await ids()).not.toContain('osv');
    await seedRun('r3', 'nvd', new Date(NOW.getTime() - 7 * HOUR), 'running');
    expect(await ids()).toContain('nvd');
  });

  it('KV overrides: ingest:false drops an on source, ingest:true adds a wait one, junk keeps wait off', async () => {
    expect(SOURCE_BY_ID.get('ransomware-live')?.licence).toBe('wait');
    expect(await ids()).not.toContain('ransomware-live');
    await E.SETTINGS.put('source:cve-list', '{"ingest":false}');
    await E.SETTINGS.put('source:ransomware-live', '{"ingest":true}');
    await E.SETTINGS.put('source:vulncheck', '{"ingest":"true"}');
    await E.SETTINGS.put('source:zdi', 'not json');
    const got = await ids();
    expect(got).not.toContain('cve-list');
    expect(got).toContain('ransomware-live');
    expect(got).not.toContain('vulncheck');
  });

  it('carries the stored cursor as `from`', async () => {
    await seedCursor('osv', { kind: 'timestamp', value: 't0', etag: 'e0' });
    const due = await dueSources(E, CRON, NOW);
    expect(due.find((d) => d.source.id === 'osv')?.from).toEqual({
      kind: 'timestamp',
      value: 't0',
      etag: 'e0',
    });
    expect(due.find((d) => d.source.id === 'cve-list')?.from).toBeNull();
  });

  it('the nightly cron has no sources', async () => {
    expect(await dueSources(E, '30 2 * * *', NOW)).toEqual([]);
  });
});

describe('plan', () => {
  it('sends one step-0 message per due source with distinct ULID run ids', async () => {
    const { sent, queue } = fakeJobs();
    const notify: unknown[] = [];
    const env = { ...E, JOBS: queue, NOTIFY: { send: async (m: unknown) => notify.push(m) } } as never;
    await worker.scheduled({ cron: CRON, scheduledTime: NOW.getTime() } as ScheduledController, env);
    const due = await dueSources(E, CRON, NOW);
    expect(sent.map((m) => m.sourceId).sort()).toEqual(due.map((d) => d.source.id).sort());
    expect(due.length).toBeGreaterThan(0);
    for (const m of sent) {
      expect(m.runId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
      expect(m.step).toBe(0);
      expect(m.from).toBeNull();
    }
    expect(new Set(sent.map((m) => m.runId)).size).toBe(sent.length);
    expect(notify).toHaveLength(1);
  });

  it('notifies only on the 3-hourly cron', async () => {
    const { queue } = fakeJobs();
    const notify: unknown[] = [];
    const env = { ...E, JOBS: queue, NOTIFY: { send: async (m: unknown) => notify.push(m) } } as never;
    await plan({ cron: '0 5 * * 1', scheduledTime: NOW.getTime() } as ScheduledController, env, {
      newId: () => 'x',
    });
    expect(notify).toHaveLength(0);
  });

  it('sends in chunks of at most 100', async () => {
    const sizes: number[] = [];
    const JOBS = { sendBatch: async (m: unknown[]) => void sizes.push(m.length) } as never;
    await plan(
      { cron: CRON, scheduledTime: NOW.getTime() } as ScheduledController,
      { ...E, JOBS, NOTIFY: { send: async () => {} } } as never,
      {
        newId: () => 'id',
      },
    );
    expect(sizes.every((n) => n <= 100)).toBe(true);
  });
});
