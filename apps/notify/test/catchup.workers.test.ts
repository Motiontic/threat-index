import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { consume, runNotify } from '../src/consume';
import {
  MAX_CHANGES_PER_RUN,
  MAX_EMAILS_PER_RUN,
  MAX_PAGES_PER_RUN,
  RUN_TIME_BUDGET_MS,
} from '../src/limits';
import {
  captureLogs,
  E,
  fakeBatch,
  fakeFetch,
  MON_9,
  queueOf,
  reset,
  rows,
  seedAffected,
  seedPkgWatch,
  seedSearch,
  seedUser,
  seedVuln,
  seedWatch,
  T,
  withKey,
} from './helpers';

let logs: ReturnType<typeof captureLogs>;
beforeEach(async () => {
  await reset();
  logs = captureLogs();
});
afterEach(() => {
  logs.restore();
  for (const l of logs.lines) expect(l).not.toContain('@');
});

const cursor = async () =>
  JSON.parse(
    (await rows<{ value: string }>("SELECT value FROM notify_state WHERE name = 'cursor'"))[0]?.value ?? '{}',
  );
const event = (name: string) =>
  logs.lines
    .filter((l) => l.includes(`"event":"${name}"`))
    .map((l) => JSON.parse(l) as Record<string, unknown>);

/** `n` changes at one `at`, ids c00000…; entity cycles through `keys`. */
async function seedChanges(
  n: number,
  at: string,
  keys: string[] = ['CVE-A'],
  from = 0,
  kind = 'public_exploit',
) {
  for (let i = 0; i < n; i += 400) {
    await E.DB_SIGNALS.batch(
      Array.from({ length: Math.min(400, n - i) }, (_, j) => {
        const k = from + i + j;
        return E.DB_SIGNALS.prepare(
          "INSERT INTO changes (id, entity_key, kind, at, source) VALUES (?1, ?2, ?3, ?4, 'osv')",
        ).bind(`c${String(k).padStart(5, '0')}`, keys[k % keys.length], kind, at);
      }),
    );
  }
}
const quiet = { ...fakeFetch().deps };

async function seedCursor(at: string, id: string) {
  await E.DB_USERS.prepare("INSERT INTO notify_state (name, value, updated_at) VALUES ('cursor', ?1, ?2)")
    .bind(JSON.stringify({ at, id, since: '2026-11-20T00:00:00.000Z' }), at)
    .run();
}

describe('catch-up: several pages a run', () => {
  it('1,300 changes sharing one `at` take three pages in one run; the next run reads none', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('06:00'), '');
    await seedChanges(1300, T('07:00'));
    await runNotify(withKey(), MON_9, quiet);
    expect(await cursor()).toMatchObject({ at: T('07:00'), id: 'c01299' });
    expect(event('notify.run')[0]).toMatchObject({ pages: 3 });
    expect(event('notify.behind')).toEqual([]);
    logs.lines.length = 0;
    await runNotify(withKey(), new Date('2026-11-23T12:00:00.000Z'), quiet);
    expect(event('notify.run')[0]).toMatchObject({ pages: 1 });
    // The second run's only rows are the late window, which was matched already.
    expect(await cursor()).toMatchObject({ id: 'c01299' });
  });

  it('page budget: stops after MAX_PAGES_PER_RUN, logs behind, next run carries on without duplicates', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('06:00'), '');
    const total = MAX_PAGES_PER_RUN * MAX_CHANGES_PER_RUN + 300;
    await seedChanges(total, T('07:00'), ['CVE-A', 'CVE-B', 'CVE-B', 'CVE-B']);
    const stop = MAX_PAGES_PER_RUN * MAX_CHANGES_PER_RUN - 1;
    await runNotify(withKey(), MON_9, quiet);
    expect(await cursor()).toMatchObject({ id: `c${String(stop).padStart(5, '0')}` });
    expect(event('notify.run')[0]).toMatchObject({ pages: MAX_PAGES_PER_RUN });
    expect(event('notify.behind')).toEqual([
      { event: 'notify.behind', pages: MAX_PAGES_PER_RUN, read: stop + 1, lagHours: 2 },
    ]);
    const first = (await queueOf('u1')).map((r) => r.change_id);
    await runNotify(withKey(), new Date('2026-11-23T12:00:00.000Z'), quiet);
    expect((await cursor()).id).toBe(`c${String(total - 1).padStart(5, '0')}`);
    const all = (await queueOf('u1')).map((r) => r.change_id);
    expect(new Set(all).size).toBe(all.length);
    expect(all.length).toBeGreaterThanOrEqual(first.length);
  });

  it('time budget: a clock past the budget after page 1 stops the run after page 1', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('06:00'), '');
    await seedChanges(1200, T('07:00'));
    let t = 0;
    // First call is the run start; every later call is after the budget.
    const now = () => (t++ === 0 ? 0 : RUN_TIME_BUDGET_MS);
    await runNotify(withKey(), MON_9, { ...quiet, now });
    expect(event('notify.run')[0]).toMatchObject({ pages: 1 });
    expect(event('notify.behind')).toHaveLength(1);
    expect((await cursor()).id).toBe('c00499');
  });

  it('reads the late window once, on the first page only', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('07:00'), 'a');
    await seedChanges(1100, T('08:00'));
    const queries: string[] = [];
    const spy = {
      ...E,
      DB_SIGNALS: new Proxy(E.DB_SIGNALS, {
        get: (t, p) =>
          p === 'prepare'
            ? (sql: string) => {
                queries.push(sql);
                return t.prepare(sql);
              }
            : Reflect.get(t, p).bind?.(t),
      }),
    } as typeof E;
    await runNotify({ ...spy, RESEND_API_KEY: 're_test' }, MON_9, quiet);
    expect(queries.filter((q) => q.includes('at > ?1 AND at <= ?2'))).toHaveLength(1);
    expect(queries.filter((q) => q.includes('OR (at = ?1 AND id > ?2)'))).toHaveLength(3);
  });

  it("page 2's batch failing keeps page 1; the retry queues no duplicates", async () => {
    const keys = ['K0', 'K1', 'K2', 'K3', 'K4', 'K5'];
    for (const [i, k] of keys.entries()) {
      await seedUser(`u${i}`, { instant: 0, digest: 'daily' });
      await seedWatch(`u${i}`, k);
    }
    await seedCursor(T('06:00'), '');
    await seedChanges(1100, T('07:00'), keys);
    // Fail the second page's match batch by breaking the stored cursor write: count `batch` calls on DB_USERS.
    let n = 0;
    const failing = {
      ...withKey(),
      DB_USERS: new Proxy(E.DB_USERS, {
        get: (t, p) =>
          p === 'batch'
            ? (stmts: D1PreparedStatement[]) => {
                if (++n === 2) throw new Error('d1 down');
                return t.batch(stmts);
              }
            : ((Reflect.get(t, p) as { bind?: (x: unknown) => unknown }).bind?.(t) ?? Reflect.get(t, p)),
      }),
    } as typeof E;
    const m = fakeBatch({ kind: 'run-finished', at: MON_9.getTime() });
    await consume(m.batch, failing, { ...quiet, now: () => MON_9.getTime() });
    expect(m.calls.ack).toBe(0);
    expect(m.calls.retry).toEqual([{ delaySeconds: 300 }]);
    expect((await cursor()).id).toBe('c00499');
    const after1 = await rows<{ n: number }>('SELECT COUNT(*) AS n FROM alert_queue');
    expect(after1[0]?.n).toBe(500);
    const m2 = fakeBatch({ kind: 'run-finished', at: MON_9.getTime() });
    await consume(m2.batch, withKey(), { ...quiet, now: () => MON_9.getTime() });
    expect(m2.calls.ack).toBe(1);
    const all = (await rows<{ change_id: string }>('SELECT change_id FROM alert_queue')).map(
      (r) => r.change_id,
    );
    expect(all).toHaveLength(1100);
    expect(new Set(all).size).toBe(1100);
  });
});

/** Counts D1 calls the way Cloudflare does: each first/all/run/raw is one; a batch() is one however many statements it holds. */
function counted(db: D1Database, tally: { n: number }): D1Database {
  const wrapStmt = (s: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(s, {
      get: (t, p) => {
        if (p === '__inner') return t;
        const v = Reflect.get(t, p) as (...a: unknown[]) => unknown;
        if (p === 'bind') return (...a: unknown[]) => wrapStmt(v.apply(t, a) as D1PreparedStatement);
        if (p === 'first' || p === 'all' || p === 'run' || p === 'raw')
          return (...a: unknown[]) => {
            tally.n++;
            return v.apply(t, a);
          };
        return v.bind(t);
      },
    });
  return new Proxy(db, {
    get: (t, p) => {
      if (p === 'prepare') return (sql: string) => wrapStmt(t.prepare(sql));
      if (p === 'batch')
        return (stmts: D1PreparedStatement[]) => {
          tally.n += 1;
          return t.batch(stmts.map((s) => (s as unknown as { __inner: D1PreparedStatement }).__inner));
        };
      return (Reflect.get(t, p) as { bind: (x: unknown) => unknown }).bind(t);
    },
  });
}

describe('D1 calls per run', () => {
  /** One run at 03:00 (prune included) over `pages` forward pages; returns D1 calls and sends. */
  async function measure(pages: number, users = MAX_EMAILS_PER_RUN + 5) {
    await reset();
    logs.lines.length = 0;
    // Entry watches, package watches and saved searches all present; every page matches all of them.
    for (let u = 0; u < users; u++) {
      await seedUser(`u${u}`, { instant: 1, digest: 'off' });
      await seedWatch(`u${u}`, 'CVE-A');
      await seedPkgWatch(`u${u}`, 'npm', 'shared');
      await seedSearch(`u${u}`, 's1', 'alpha', {});
    }
    await seedVuln('CVE-A', 'Alpha gateway flaw');
    await seedAffected('npm', 'shared', 'osv', 'S1', 'CVE-A', '1.2.3');
    await seedCursor(T('02:00'), '');
    // The last page is short, so the run ends caught up after exactly `pages` pages.
    await seedChanges(pages * MAX_CHANGES_PER_RUN - 1, T('02:30'), ['CVE-A']);
    const tally = { n: 0 };
    const env = {
      ...withKey(),
      DB_SIGNALS: counted(E.DB_SIGNALS, tally),
      DB_USERS: counted(E.DB_USERS, tally),
      DB_VULNS: counted(E.DB_VULNS, tally),
      DB_ADVISORIES: counted(E.DB_ADVISORIES, tally),
      DB_WORLD: counted(E.DB_WORLD, tally),
    } as typeof E;
    const f = fakeFetch();
    await runNotify(env, new Date('2026-11-23T03:00:00.000Z'), f.deps);
    expect(event('notify.run')[0]).toMatchObject({ pages });
    return { calls: tally.n, sends: f.sent.length };
  }

  it('measures one page and the rest of a run, and a whole 8-page run stays under 500', async () => {
    const one = await measure(1);
    const two = await measure(2);
    const perPage = two.calls - one.calls;
    const fixed = one.calls - perPage;
    const full = await measure(MAX_PAGES_PER_RUN);
    const few = await measure(1, 5);
    const perSend = (one.calls - few.calls) / (one.sends - few.sends);
    console.info(
      `D1 calls: 1 page ${one.calls}, 2 pages ${two.calls}, ${MAX_PAGES_PER_RUN} pages ${full.calls}; per page ${perPage}, rest of run ${fixed} (includes ${one.sends} sends; ${few.sends} sends cost ${few.calls - perPage}); sends ${full.sends} (cap ${MAX_EMAILS_PER_RUN}); per send ${perSend}`,
    );
    expect(full.sends).toBe(MAX_EMAILS_PER_RUN);
    expect(full.calls).toBeLessThan(500);
  });
});

describe('quiet rows', () => {
  const quietise = (ids: string[], why = 'first_load') =>
    E.DB_SIGNALS.batch(
      ids.map((id) => E.DB_SIGNALS.prepare('UPDATE changes SET quiet = ?1 WHERE id = ?2').bind(why, id)),
    );

  it('the forward read never queues a quiet row, and quiet rows before an alertable one do not hide it', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('06:00'), '');
    // 1,100 quiet rows fill more than a page ahead of the one alertable row.
    await seedChanges(1100, T('07:00'));
    await quietise(Array.from({ length: 1100 }, (_, i) => `c${String(i).padStart(5, '0')}`), 'old');
    await seedChanges(1, T('07:30'), ['CVE-A'], 5000);
    await runNotify(withKey(), MON_9, quiet);
    expect((await queueOf('u1')).map((r) => r.change_id)).toEqual(['c05000']);
    expect(await cursor()).toMatchObject({ id: 'c05000' });
  });

  it('the late read never queues a quiet row', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('08:00'), 'z');
    // Written after the cursor passed their time: one alertable, one held, one old.
    await seedChanges(3, T('07:00'));
    await quietise(['c00001'], 'held');
    await quietise(['c00002'], 'old');
    await runNotify(withKey(), MON_9, quiet);
    expect((await queueOf('u1')).map((r) => r.change_id)).toEqual(['c00000']);
  });

  it('a run of only quiet rows queues nothing and leaves the cursor alone', async () => {
    await seedUser('u1', { instant: 0, digest: 'daily' });
    await seedWatch('u1', 'CVE-A');
    await seedCursor(T('06:00'), '');
    await seedChanges(5, T('07:00'));
    await quietise(['c00000', 'c00001', 'c00002', 'c00003', 'c00004']);
    await runNotify(withKey(), MON_9, quiet);
    expect(await queueOf('u1')).toEqual([]);
    expect(await cursor()).toMatchObject({ at: T('06:00'), id: '' });
  });
});
