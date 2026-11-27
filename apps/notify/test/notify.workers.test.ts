import { emailIdempotencyKey } from '@ti/core/email';
import { verifyUnsubscribeToken } from '@ti/core/unsubscribe';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { consume, runNotify } from '../src/consume';
import {
  captureLogs,
  E,
  fakeBatch,
  fakeFetch,
  MON_3,
  MON_9,
  queueOf,
  reset,
  rows,
  seedChange,
  seedEmailLog,
  seedSearch,
  seedUser,
  seedVuln,
  seedWatch,
  T,
  TUE_9,
  withKey,
} from './helpers';

let logs: ReturnType<typeof captureLogs>;
beforeEach(async () => {
  await reset();
  logs = captureLogs();
});
afterEach(() => {
  logs.restore();
  // No logged line may hold an address.
  for (const l of logs.lines) expect(l).not.toContain('@');
});

const sends = () =>
  rows<{ idem_key: string; kind: string; status: string; provider_id: string | null }>(
    'SELECT * FROM email_sends ORDER BY idem_key',
  );
const sentCount = async (day = '2026-11-23') =>
  (await rows<{ sent: number }>('SELECT sent FROM email_log WHERE day = ?1', day))[0]?.sent;
const sentChanges = (user: string) =>
  rows<{ change_id: string }>(
    'SELECT change_id FROM alerts_sent WHERE user_id = ?1 ORDER BY change_id',
    user,
  );

async function seedInstantScenario() {
  await seedUser('u1', { instant: 1, digest: 'off' });
  await seedWatch('u1', 'CVE-A');
  await seedWatch('u1', 'CVE-B');
  await seedVuln('CVE-A', 'Alpha gateway flaw');
  await seedVuln('CVE-B', 'Beta router flaw');
  await seedChange('c1', 'CVE-A', 'newly_exploited', T('07:00'));
  await seedChange('c2', 'CVE-B', 'public_exploit', T('07:30'));
  await seedChange('c3', 'CVE-A', 'fix_released', T('08:00'));
}

describe('instant alerts', () => {
  it('1. sends one email with the right request and does the bookkeeping', async () => {
    await seedInstantScenario();
    const f = fakeFetch();
    await runNotify(withKey(), MON_9, f.deps);
    expect(f.bad).toEqual([]);
    expect(f.sent).toHaveLength(1);
    const r = f.sent[0];
    expect(r?.headers.authorization).toBe('Bearer re_test');
    expect(r?.headers['idempotency-key']).toBe(
      await emailIdempotencyKey('u1', 'instant', ['c1', 'c2', 'c3']),
    );
    expect(r?.body.to).toEqual(['u1@example.com']);
    const lu = r?.body.headers['List-Unsubscribe'] ?? '';
    expect(lu).toMatch(/^<https?:\/\/.+\/unsubscribe\?t=.+>$/);
    expect(r?.body.headers['List-Unsubscribe-Post']).toBe('List-Unsubscribe=One-Click');
    const token = new URL(lu.slice(1, -1)).searchParams.get('t');
    // A token from the notify worker passes the API's verifier.
    expect(await verifyUnsubscribeToken('test-unsubscribe-secret', token)).toMatchObject({
      userId: 'u1',
      scope: 'all',
    });
    for (const part of [r?.body.text, r?.body.html]) {
      expect(part).toContain('/e/CVE-A');
      expect(part).toContain('/e/CVE-B');
      expect(part).toContain(SOURCE_BY_ID.get('osv')?.credit);
    }
    expect(r?.body.html).toContain(lu.slice(1, -1).replace(/&/g, '&#38;'));
    expect(await sentChanges('u1')).toHaveLength(3);
    expect(await queueOf('u1')).toEqual([]);
    expect((await sends()).map((s) => [s.kind, s.status, s.provider_id])).toEqual([
      ['instant', 'sent', 're_id'],
    ]);
    expect(await sentCount()).toBe(1);
  });

  it('1b. an email about one watched entry uses the watch scope with that entry', async () => {
    await seedUser('u1');
    await seedWatch('u1', 'CVE-A');
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('08:00'));
    const f = fakeFetch();
    await runNotify(withKey(), MON_9, f.deps);
    const lu = f.sent[0]?.body.headers['List-Unsubscribe'] ?? '';
    const p = await verifyUnsubscribeToken(
      'test-unsubscribe-secret',
      new URL(lu.slice(1, -1)).searchParams.get('t'),
    );
    expect(p).toMatchObject({ userId: 'u1', scope: 'watch', item: 'CVE-A' });
  });

  it('2. the same message again sends nothing; a crash replay reuses the idempotency key', async () => {
    await seedInstantScenario();
    const f = fakeFetch();
    const m1 = fakeBatch({ kind: 'run-finished', at: MON_9.getTime() });
    await consume(m1.batch, withKey(), { ...f.deps, now: () => MON_9.getTime() });
    expect(m1.calls.ack).toBe(1);
    expect(f.sent).toHaveLength(1);
    const m2 = fakeBatch({ kind: 'run-finished', at: MON_9.getTime() });
    await consume(m2.batch, withKey(), { ...f.deps, now: () => MON_9.getTime() });
    expect(f.sent).toHaveLength(1);

    // Crash after the request but before the bookkeeping: pending row and queue rows are left.
    await reset();
    await seedInstantScenario();
    const key = await emailIdempotencyKey('u1', 'instant', ['c1', 'c2', 'c3']);
    await E.DB_USERS.prepare(
      "INSERT INTO email_sends (idem_key, kind, change_count, status, created_at, updated_at) VALUES (?1,'instant',3,'pending','x','x')",
    )
      .bind(key)
      .run();
    for (const c of ['c1', 'c2', 'c3'])
      await E.DB_USERS.prepare(
        "INSERT INTO alert_queue (user_id, change_id, created_at, via) VALUES ('u1', ?1, 'x', 'watch')",
      )
        .bind(c)
        .run();
    const g = fakeFetch();
    await runNotify(withKey(), MON_9, g.deps);
    expect(g.sent).toHaveLength(1);
    expect(g.sent[0]?.headers['idempotency-key']).toBe(key);
    expect((await sends())[0]?.status).toBe('sent');
    expect(await queueOf('u1')).toEqual([]);
  });
});

describe('digests', () => {
  it('3. daily waits for 03:00; weekly waits for its weekday', async () => {
    await seedUser('d', { instant: 0, digest: 'daily' });
    await seedUser('w', { instant: 0, digest: 'weekly', weekday: 1 });
    await seedUser('w2', { instant: 0, digest: 'weekly', weekday: 3 });
    for (const u of ['d', 'w', 'w2']) await seedWatch(u, 'CVE-A');
    await seedVuln('CVE-A', 'Alpha');
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('08:00'));
    const f = fakeFetch();
    await runNotify(withKey(), MON_9, f.deps);
    expect(f.sent).toHaveLength(0);
    for (const u of ['d', 'w', 'w2']) expect((await queueOf(u)).length).toBe(1);
    // 03:00 next day is Tuesday: daily goes, weekly (Mon, Wed) does not.
    await runNotify(withKey(), new Date('2026-11-24T03:00:00.000Z'), f.deps);
    expect(f.sent.map((s) => s.body.to[0])).toEqual(['d@example.com']);
    // Monday 03:00 a week later: weekly Monday user.
    await runNotify(withKey(), new Date('2026-11-30T03:00:00.000Z'), f.deps);
    expect(f.sent.map((s) => s.body.to[0])).toEqual(['d@example.com', 'w@example.com']);
    expect((await sends()).map((s) => s.kind).sort()).toEqual(['daily', 'weekly']);
    expect(f.sent[0]?.body.subject).toBe('MTI daily digest: 1 updates');
    const p = await verifyUnsubscribeToken(
      'test-unsubscribe-secret',
      new URL((f.sent[0]?.body.headers['List-Unsubscribe'] ?? '').slice(1, -1)).searchParams.get('t'),
    );
    expect(p?.scope).toBe('digest');
  });

  it('3b. the 03:00 run sends a daily digest (same-day queue)', async () => {
    await seedUser('d', { instant: 0, digest: 'daily' });
    await seedWatch('d', 'CVE-A');
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('02:00'));
    const f = fakeFetch();
    await runNotify(withKey(), MON_3, f.deps);
    expect(f.sent).toHaveLength(1);
  });

  it('4. an instant + daily user at 03:00 gets one email holding the watch and the search match', async () => {
    await seedUser('u1', { instant: 1, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedSearch('u1', 's1', 'beta', {});
    await seedVuln('CVE-A', 'Alpha thing');
    await seedVuln('CVE-B', 'Beta thing');
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('02:00'));
    await seedChange('c2', 'CVE-B', 'public_exploit', T('02:10'));
    const f = fakeFetch();
    await runNotify(withKey(), MON_3, f.deps);
    expect(f.sent).toHaveLength(1);
    expect(f.sent[0]?.body.text).toContain('Alpha thing');
    expect(f.sent[0]?.body.text).toContain('Matches for "Search s1"');
    expect(f.sent[0]?.body.text).toContain('Beta thing');
    expect(await queueOf('u1')).toEqual([]);
  });
});

describe('matching', () => {
  it('5. saved searches: filters, alerts_on, digest off and alert_triggers', async () => {
    await seedVuln('CVE-X', 'Acme gateway overflow', { cvss: 9.8 });
    await seedChange('c1', 'CVE-X', 'public_exploit', T('08:00'));
    await seedChange('c2', 'CVE-X', 'cvss_change', T('08:05'));
    await seedUser('hit', { instant: 0, digest: 'daily' });
    await seedSearch('hit', 'a', 'acme gateway', { sev: ['critical'] });
    await seedSearch('hit', 'b', 'acme router', {});
    await seedSearch('hit', 'c', 'acme', { sev: ['low'] });
    await seedUser('off', { instant: 0, digest: 'daily' });
    await seedSearch('off', 'a', 'acme', {}, 0);
    await seedUser('nodigest', { instant: 1, digest: 'off' });
    await seedSearch('nodigest', 'a', 'acme', {});
    await seedUser('cvss', { instant: 0, digest: 'daily', triggers: '["cvss_change"]' });
    await seedSearch('cvss', 'a', 'acme', {});
    const f = fakeFetch();
    await runNotify(withKey(), MON_9, f.deps);
    expect(await queueOf('hit')).toEqual([{ change_id: 'c1', via: 'search:a' }]);
    expect(await queueOf('off')).toEqual([]);
    expect(await queueOf('nodigest')).toEqual([]);
    expect(await queueOf('cvss')).toEqual([{ change_id: 'c2', via: 'search:a' }]);
  });

  it('5b. a watch match keeps via=watch when a search also matches; triggers filter watch rows', async () => {
    await seedVuln('CVE-X', 'Acme thing');
    await seedChange('c1', 'CVE-X', 'public_exploit', T('08:00'));
    await seedChange('c2', 'CVE-X', 'cvss_change', T('08:05'));
    await seedUser('u', { instant: 0, digest: 'daily' });
    await seedWatch('u', 'CVE-X');
    await seedSearch('u', 's', 'acme', {});
    await runNotify(withKey(), MON_9, fakeFetch().deps);
    expect(await queueOf('u')).toEqual([
      { change_id: 'c1', via: 'watch' }, // c2 (cvss_change) is not a default trigger
    ]);
  });

  it('6. suppressed and deleted users get nothing and their queue rows go', async () => {
    await seedUser('sup', { suppressed: 1 });
    await seedUser('del', { deleted: '2026-11-01T00:00:00.000Z' });
    await seedWatch('sup', 'CVE-A');
    await seedWatch('del', 'CVE-A');
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('08:00'));
    for (const u of ['sup', 'del'])
      await E.DB_USERS.prepare(
        "INSERT INTO alert_queue (user_id, change_id, created_at, via) VALUES (?1, 'c1', 'x', 'watch')",
      )
        .bind(u)
        .run();
    const f = fakeFetch();
    await runNotify(withKey(), MON_9, f.deps);
    expect(f.sent).toHaveLength(0);
    expect(await rows('SELECT * FROM alert_queue')).toEqual([]);
  });
});

describe('cap and providers', () => {
  it('7. the 75 a day alert cap holds, and the next day sends the rest', async () => {
    await seedEmailLog('2026-11-24', 0);
    await E.DB_USERS.prepare('DELETE FROM email_log').run();
    await seedEmailLog('2026-11-23', 73);
    await seedUser('inst');
    await seedWatch('inst', 'CVE-A');
    for (const u of ['d1', 'd2', 'd3']) {
      await seedUser(u, { instant: 0, digest: 'daily' });
      await seedWatch(u, 'CVE-A');
    }
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('02:00'));
    const f = fakeFetch();
    await runNotify(withKey(), MON_3, f.deps);
    expect(f.sent).toHaveLength(2);
    expect(f.sent[0]?.body.to[0]).toBe('inst@example.com'); // instant first
    expect(await sentCount()).toBe(75);
    const left = await rows<{ user_id: string }>('SELECT DISTINCT user_id FROM alert_queue ORDER BY user_id');
    expect(left).toHaveLength(2);
    await runNotify(withKey(), new Date('2026-11-24T03:00:00.000Z'), f.deps);
    expect(f.sent).toHaveLength(4);
    expect(await sentCount('2026-11-24')).toBe(2);
    expect(await rows('SELECT * FROM alert_queue')).toEqual([]);
  });

  it('8. a dry run (no key) logs, marks dry_run, counts toward the cap and never calls fetch', async () => {
    await seedInstantScenario();
    const f = fakeFetch();
    await runNotify(E, MON_9, f.deps);
    expect(f.sent).toHaveLength(0);
    expect((await sends()).map((s) => s.status)).toEqual(['dry_run']);
    expect(await queueOf('u1')).toEqual([]);
    expect(await sentCount()).toBe(1);
    expect(logs.lines.some((l) => l.includes('"notify.dry_run"'))).toBe(true);
    expect(logs.lines.some((l) => l.includes('"notify.run"'))).toBe(true);
  });

  it('8b. no unsubscribe secret: nothing is sent, matching still runs', async () => {
    await seedInstantScenario();
    const f = fakeFetch();
    await runNotify({ ...withKey(), UNSUBSCRIBE_SECRET: '' }, MON_9, f.deps);
    expect(f.sent).toHaveLength(0);
    expect((await queueOf('u1')).length).toBe(3);
    expect(logs.lines.some((l) => l.includes('notify.no_unsubscribe_secret'))).toBe(true);
  });

  it('9. a 422 fails that email and releases its slot; a 500 stops sending without throwing', async () => {
    for (const u of ['a', 'b', 'c']) {
      await seedUser(u);
      await seedWatch(u, 'CVE-A');
    }
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('08:00'));
    const f = fakeFetch((n) => (n === 1 ? new Response('{}', { status: 422 }) : Response.json({ id: 'ok' })));
    await runNotify(withKey(), MON_9, f.deps);
    expect(f.sent).toHaveLength(3);
    const st = await sends();
    expect(st.map((s) => s.status).sort()).toEqual(['failed', 'sent', 'sent']);
    expect(await sentCount()).toBe(2);
    expect(await rows('SELECT DISTINCT user_id FROM alert_queue')).toHaveLength(1);

    await reset();
    for (const u of ['a', 'b', 'c']) {
      await seedUser(u);
      await seedWatch(u, 'CVE-A');
    }
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('08:00'));
    const g = fakeFetch((n) => (n === 2 ? new Response('{}', { status: 500 }) : Response.json({ id: 'ok' })));
    await runNotify(withKey(), MON_9, g.deps);
    expect(g.sent).toHaveLength(2);
    expect(await sentCount()).toBe(1);
    expect(await rows('SELECT DISTINCT user_id FROM alert_queue')).toHaveLength(2);
  });

  it('9b. a network error stops sending without throwing', async () => {
    await seedUser('a');
    await seedWatch('a', 'CVE-A');
    await seedChange('c1', 'CVE-A', 'newly_exploited', T('08:00'));
    const deps = {
      fetch: (async () => {
        throw new TypeError('boom');
      }) as typeof fetch,
      sleep: async () => {},
    };
    await runNotify(withKey(), MON_9, deps);
    expect((await sends())[0]?.status).toBe('failed');
    expect(await sentCount()).toBe(0);
    expect((await queueOf('a')).length).toBe(1);
  });
});

describe('cursor and messages', () => {
  it('10. first run ignores old changes; late rows within 6 h are matched; sent changes never requeue', async () => {
    await seedUser('u1');
    await seedWatch('u1', 'CVE-A');
    await seedChange('old', 'CVE-A', 'newly_exploited', T('05:00')); // older than 3 h before 09:00
    await seedChange('fresh', 'CVE-A', 'public_exploit', T('08:00'));
    const f = fakeFetch();
    await runNotify(withKey(), MON_9, f.deps);
    expect(f.sent).toHaveLength(1);
    expect((await sentChanges('u1')).map((r) => r.change_id)).toEqual(['fresh']);
    const cur = await rows<{ value: string }>("SELECT value FROM notify_state WHERE name = 'cursor'");
    expect(JSON.parse(cur[0]?.value ?? '{}')).toMatchObject({ at: T('08:00'), id: 'fresh' });

    // The loader writes a row later with an `at` before the cursor.
    await seedChange('late', 'CVE-A', 'fix_released', T('07:00'));
    await runNotify(withKey(), new Date('2026-11-23T12:00:00.000Z'), f.deps);
    expect(f.sent).toHaveLength(2);
    expect((await sentChanges('u1')).map((r) => r.change_id)).toEqual(['fresh', 'late']);

    // Nothing is mailed twice, and the history ('old') stays unmailed.
    await runNotify(withKey(), new Date('2026-11-23T15:00:00.000Z'), f.deps);
    expect(f.sent).toHaveLength(2);
    expect(await queueOf('u1')).toEqual([]);
  });

  it('10b. a full forward read logs a backlog; one user is capped at 200 queued rows, the cursor still moves', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    const stmts = Array.from({ length: 501 }, (_, i) =>
      E.DB_SIGNALS.prepare(
        "INSERT INTO changes (id, entity_key, kind, at) VALUES (?1, 'CVE-A', 'public_exploit', ?2)",
      ).bind(`c${String(i).padStart(4, '0')}`, T('07:00')),
    );
    await E.DB_SIGNALS.batch(stmts);
    await runNotify(withKey(), MON_9, fakeFetch().deps);
    expect(logs.lines.some((l) => l.includes('notify.backlog'))).toBe(true);
    expect(logs.lines.some((l) => l.includes('notify.queue_capped'))).toBe(true);
    expect((await queueOf('u1')).length).toBe(200);
    await runNotify(withKey(), new Date('2026-11-23T12:00:00.000Z'), fakeFetch().deps);
    expect((await queueOf('u1')).length).toBe(200);
    const cursor = await rows<{ value: string }>("SELECT value FROM notify_state WHERE name = 'cursor'");
    expect(JSON.parse(cursor[0]?.value ?? '{}').id).toBe('c0500'); // all 501 were read across two runs
  });

  it('11. a bad message is acked and writes nothing; a D1 failure retries', async () => {
    await seedInstantScenario();
    const f = fakeFetch();
    for (const body of [
      null,
      'x',
      { kind: 'other', at: 1 },
      { kind: 'run-finished' },
      { kind: 'run-finished', at: 'now' },
      { kind: 'run-finished', at: 1 },
    ]) {
      const m = fakeBatch(body);
      await consume(m.batch, withKey(), { ...f.deps, now: () => MON_9.getTime() });
      expect(m.calls.ack).toBe(1);
      expect(m.calls.retry).toEqual([]);
    }
    expect(f.sent).toHaveLength(0);
    expect(await rows('SELECT * FROM notify_state')).toEqual([]);
    expect(await rows('SELECT * FROM alert_queue')).toEqual([]);

    await seedSearch('u1', 's1', 'alpha', {});
    const broken = {
      ...withKey(),
      DB_VULNS: {
        prepare: () => {
          throw new Error('d1 down');
        },
      } as unknown as D1Database,
    };
    const m = fakeBatch({ kind: 'run-finished', at: MON_9.getTime() });
    await consume(m.batch, broken, { ...f.deps, now: () => MON_9.getTime() });
    expect(m.calls.ack).toBe(0);
    expect(m.calls.retry).toEqual([{ delaySeconds: 300 }]);
    expect(await rows('SELECT * FROM notify_state')).toEqual([]);
  });

  it('prunes on the 03:00 run', async () => {
    await seedUser('u1', { instant: 0, digest: 'off' });
    await seedEmailLog('2026-09-01', 5);
    await seedEmailLog('2026-11-22', 5);
    const old = '2026-09-01T00:00:00.000Z';
    await E.DB_USERS.batch([
      E.DB_USERS.prepare(
        "INSERT INTO alert_queue (user_id, change_id, created_at, via) VALUES ('u1','q-old',?1,'watch')",
      ).bind(old),
      E.DB_USERS.prepare(
        "INSERT INTO alerts_sent (user_id, change_id, sent_at) VALUES ('u1','s-old',?1)",
      ).bind(old),
      E.DB_USERS.prepare(
        "INSERT INTO email_sends (idem_key, kind, change_count, status, created_at, updated_at) VALUES ('k','daily',1,'sent',?1,?1)",
      ).bind(old),
    ]);
    await runNotify(withKey(), TUE_9, fakeFetch().deps); // not 03:00: nothing pruned
    expect(await rows('SELECT * FROM email_sends')).toHaveLength(1);
    await runNotify(withKey(), new Date('2026-11-24T03:00:00.000Z'), fakeFetch().deps);
    expect(await rows('SELECT * FROM email_sends')).toHaveLength(0);
    expect(await rows('SELECT * FROM alerts_sent')).toHaveLength(0);
    expect((await rows<{ day: string }>('SELECT day FROM email_log')).map((r) => r.day)).toEqual([
      '2026-11-22',
    ]);
  });
});
