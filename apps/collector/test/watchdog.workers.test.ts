import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../src/index';
import { runWatchdog } from '../src/watchdog';
import { E, HOUR, NOW, newRunId, reset, seedRun } from './helpers';

const DAY = 24 * HOUR;
// workerd keeps the raw message under an internal key on the EmailMessage object.
const rawOf = (m: object) => new Response((m as Record<string, BodyInit>)['EmailMessage::raw']).text();
const deps = () => {
  const logs: string[] = [];
  return {
    logs,
    now: () => NOW,
    newId: () => '01JABCDEFGHJKMNPQRSTVWXYZ0',
    log: (m: string, x?: object) => logs.push(JSON.stringify({ m, ...x })),
  };
};
const ago = (ms: number) => new Date(NOW.getTime() - ms);

beforeEach(reset);

async function seedAll() {
  // a daily source that succeeded 5 days ago: late
  await seedRun(newRunId(), 'cpe-dictionary', ago(5 * DAY), 'ok', { found: 10 });
  // a failing source
  await seedRun(newRunId(), 'osv', ago(2 * HOUR), 'failed', { error: 'Error: boom' });
  await seedRun(newRunId(), 'osv', ago(1 * HOUR), 'failed', { error: 'Error: latest boom' });
  // a daily source whose found dropped: 100 before, 10 now
  await seedRun(newRunId(), 'trickest-cve', ago(10 * DAY), 'ok', { found: 100 });
  await seedRun(newRunId(), 'trickest-cve', ago(2 * DAY), 'ok', { found: 10 });
  // unknown fields seen in the window
  await E.SETTINGS.put(
    'unknown-fields:cisa-kev',
    JSON.stringify({
      fields: ['zzz'],
      firstSeen: ago(HOUR).toISOString(),
      lastSeen: ago(HOUR).toISOString(),
    }),
  );
  await E.SETTINGS.put(
    'unknown-fields:old',
    JSON.stringify({
      fields: ['q'],
      firstSeen: ago(9 * DAY).toISOString(),
      lastSeen: ago(9 * DAY).toISOString(),
    }),
  );
  // budget
  await E.DB_CONTROL.prepare('INSERT INTO budget (day, d1_writes, emails_sent) VALUES (?1, 1300000, 90)')
    .bind('2026-11-23')
    .run();
  // jobs
  await E.DB_CONTROL.batch([
    E.DB_CONTROL.prepare(
      "INSERT INTO jobs (id, kind, source_id, status, created_at, finished_at) VALUES ('j-failed','big-file','osv','failed',?1,?1)",
    ).bind(ago(3 * HOUR).toISOString()),
    E.DB_CONTROL.prepare(
      "INSERT INTO jobs (id, kind, source_id, status, created_at) VALUES ('j-stuck','epss-diff','epss','running',?1)",
    ).bind(ago(2 * HOUR).toISOString()),
    E.DB_CONTROL.prepare(
      "INSERT INTO jobs (id, kind, source_id, status, created_at) VALUES ('j-young','epss-diff','epss','running',?1)",
    ).bind(ago(10 * 60_000).toISOString()),
    E.DB_CONTROL.prepare(
      "INSERT INTO jobs (id, kind, source_id, status, created_at, finished_at) VALUES ('j-done','big-file','osv','complete',?1,?1)",
    ).bind(ago(HOUR).toISOString()),
  ]);
}

describe('runWatchdog', () => {
  it('seeded rows give each finding', async () => {
    await seedAll();
    const found = await runWatchdog(E, deps());
    const by = (kind: string) => found.filter((f) => f.kind === kind);
    expect(by('late').map((f) => f.subject)).toContain('cpe-dictionary');
    expect(by('late').find((f) => f.subject === 'cve-list')?.detail).toBe('never run');
    expect(by('late').map((f) => f.subject)).not.toContain('ransomware-live'); // wait: off
    expect(by('drop').map((f) => f.subject)).toEqual(['trickest-cve']);
    expect(by('unknown-fields').map((f) => f.subject)).toEqual(['cisa-kev']);
    expect(
      by('budget')
        .map((f) => f.subject)
        .sort(),
    ).toEqual(['D1 writes 2026-11-23', 'emails 2026-11-23']);
    const failed = by('failed-runs');
    expect(failed.map((f) => f.subject)).toEqual(['osv']);
    expect(failed[0]?.detail).toContain('2 failed');
    expect(failed[0]?.detail).toContain('latest boom');
    expect(
      by('jobs')
        .map((f) => f.subject)
        .sort(),
    ).toEqual(['j-failed', 'j-stuck']);
  });

  it('a fake OPS_EMAIL gets exactly one message, with the headers the spec lists', async () => {
    await seedAll();
    const sent: { from: string; to: string; raw: string }[] = [];
    const OPS_EMAIL = {
      send: async (m: { from: string; to: string }) => {
        sent.push({ from: m.from, to: m.to, raw: await rawOf(m) });
      },
    };
    const env = {
      ...E,
      OPS_EMAIL,
      OPS_EMAIL_TO: 'ops@example.com',
      OPS_EMAIL_FROM: 'watchdog@example.org',
    } as never;
    const d = deps();
    await runWatchdog(env, d);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ from: 'watchdog@example.org', to: 'ops@example.com' });
    const raw = sent[0]?.raw as string;
    expect(raw).toContain('Subject: Threat Index watchdog 2026-11-23:');
    expect(raw).toContain('Message-ID: <01JABCDEFGHJKMNPQRSTVWXYZ0@example.org>');
    expect(raw).toContain('\r\n');
    expect(d.logs.join('\n')).not.toContain('ops@example.com');
  });

  it('sends the heartbeat when clear', async () => {
    const sent: string[] = [];
    const OPS_EMAIL = {
      send: async (m: object) => void sent.push(await rawOf(m)),
    };
    // every ingest-on source has a fresh success, so nothing is late
    const { SOURCES } = await import('@ti/sources/registry');
    const { canIngest } = await import('@ti/core/licence');
    for (const s of SOURCES) if (canIngest(s.licence)) await seedRun(newRunId(), s.id, ago(HOUR), 'ok');
    await runWatchdog(
      { ...E, OPS_EMAIL, OPS_EMAIL_TO: 'ops@example.com', OPS_EMAIL_FROM: 'w@example.org' } as never,
      deps(),
    );
    expect(sent).toHaveLength(1);
    expect(sent[0]).toContain('all clear');
  });

  it('no binding: logged, no throw', async () => {
    const d = deps();
    const found = await runWatchdog(E, d);
    expect(found.length).toBeGreaterThan(0);
    expect(d.logs.join('\n')).toContain('email skipped');
  });
});

describe('scheduled on the daily cron', () => {
  it('runs the watchdog even when plan() throws, then rethrows', async () => {
    const logs: string[] = [];
    const orig = console.log;
    console.log = (m: string) => logs.push(m);
    try {
      const env = {
        ...E,
        JOBS: {
          sendBatch: async () => {
            throw new Error('queue down');
          },
        },
      } as never;
      await expect(
        worker.scheduled({ cron: '45 14 * * *', scheduledTime: NOW.getTime() } as ScheduledController, env),
      ).rejects.toThrow('queue down');
    } finally {
      console.log = orig;
    }
    expect(logs.join('\n')).toContain('email skipped');
  });
});
