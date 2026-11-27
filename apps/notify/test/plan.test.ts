import { describe, expect, it } from 'vitest';
import type { Change } from '../src/collect';
import { plan, type QueueRow } from '../src/plan';

const change = (id: string, at: string, key = 'CVE-1'): Change => ({
  id,
  entity_key: key,
  kind: 'newly_exploited',
  old: null,
  new: '2026-11-20',
  at,
  source: 'osv',
});
const row = (userId: string, changeId: string, o: Partial<QueueRow> = {}): QueueRow => ({
  userId,
  changeId,
  via: 'watch',
  createdAt: '2026-11-23T01:00:00.000Z',
  email: `${userId}@example.com`,
  alertInstant: 1,
  digest: 'off',
  digestWeekday: 1,
  suppressed: 0,
  deleted: null,
  ...o,
});
const changes = (...cs: Change[]) => new Map(cs.map((c) => [c.id, c]));
const MON_9 = new Date('2026-11-23T09:00:00Z'); // Monday
const MON_3 = new Date('2026-11-23T03:00:00Z');

describe('plan', () => {
  it('instant items go out instantly, newest first', () => {
    const p = plan(
      [row('u1', 'a'), row('u1', 'b')],
      changes(change('a', '2026-11-23T01:00:00Z'), change('b', '2026-11-23T02:00:00Z')),
      MON_9,
    );
    expect(p.emails).toHaveLength(1);
    expect(p.emails[0]?.kind).toBe('instant');
    expect(p.emails[0]?.items.map((i) => i.changeId)).toEqual(['b', 'a']);
  });
  it('search rows wait for a digest', () => {
    const cs = changes(change('a', '2026-11-23T01:00:00Z'));
    const r = [row('u1', 'a', { via: 'search:s1', digest: 'daily' })];
    expect(plan(r, cs, MON_9).emails).toHaveLength(0);
    expect(plan(r, cs, MON_3).emails[0]?.kind).toBe('daily');
  });
  it('weekly is due only on its weekday at 03:00', () => {
    const cs = changes(change('a', '2026-11-23T01:00:00Z'));
    const r = (wd: number) => [row('u1', 'a', { alertInstant: 0, digest: 'weekly', digestWeekday: wd })];
    expect(plan(r(2), cs, MON_3).emails).toHaveLength(0);
    expect(plan(r(1), cs, MON_9).emails).toHaveLength(0);
    expect(plan(r(1), cs, MON_3).emails[0]?.kind).toBe('weekly');
  });
  it('a user gets one email: the digest, holding instant and search items', () => {
    const cs = changes(change('a', '2026-11-23T01:00:00Z'), change('b', '2026-11-23T02:00:00Z'));
    const p = plan(
      [row('u1', 'a', { digest: 'daily' }), row('u1', 'b', { digest: 'daily', via: 'search:s' })],
      cs,
      MON_3,
    );
    expect(p.emails).toHaveLength(1);
    expect(p.emails[0]?.kind).toBe('daily');
    expect(p.emails[0]?.priority).toBe(0);
    expect(p.emails[0]?.items).toHaveLength(2);
  });
  it('drops rows of suppressed, deleted, email-less users and of missing changes', () => {
    const cs = changes(change('a', '2026-11-23T01:00:00Z'));
    const p = plan(
      [
        row('s', 'a', { suppressed: 1 }),
        row('d', 'a', { deleted: 'x' }),
        row('e', 'a', { email: '' }),
        row('m', 'gone'),
      ],
      cs,
      MON_9,
    );
    expect(p.emails).toHaveLength(0);
    expect(p.drop).toHaveLength(4);
  });
  it('caps items at 50 and emails at 40, instant first', () => {
    const many = Array.from({ length: 60 }, (_, i) =>
      change(`c${String(i).padStart(2, '0')}`, `2026-11-23T01:${String(i).padStart(2, '0')}:00Z`),
    );
    const rows = many.map((c) => row('u0', c.id));
    const p = plan(rows, changes(...many), MON_9);
    expect(p.emails[0]?.items).toHaveLength(50);
    expect(p.emails[0]?.items[0]?.changeId).toBe('c59');

    const c1 = change('x', '2026-11-23T01:00:00Z');
    const users = Array.from({ length: 45 }, (_, i) =>
      row(`d${String(i).padStart(2, '0')}`, 'x', {
        alertInstant: 0,
        digest: 'daily',
        createdAt: '2026-11-23T00:00:00.000Z',
      }),
    );
    const inst = row('zzz', 'x', { createdAt: '2026-11-23T02:00:00.000Z' });
    const q = plan([...users, inst], changes(c1), MON_3);
    expect(q.emails).toHaveLength(40);
    expect(q.emails[0]?.userId).toBe('zzz');
    expect(q.emails[1]?.userId).toBe('d00');
  });
});

describe('plan: package rows and the per-user instant cap', () => {
  const c = changes(change('c1', '2026-11-23T01:00:00Z'));
  it('a pkg: row is an instant item', () => {
    const p = plan([row('u1', 'c1', { via: 'pkg:PyPI/langchain' })], c, MON_9);
    expect(p.emails.map((e) => e.kind)).toEqual(['instant']);
  });
  it('a user with 5 instant emails today gets none; 4 still gets one; items go to the digest at 03:00', () => {
    const r = [row('u1', 'c1', { via: 'pkg:npm/x', digest: 'daily' })];
    expect(plan(r, c, MON_9, new Map([['u1', 5]])).emails).toEqual([]);
    expect(plan(r, c, MON_9, new Map([['u1', 4]])).emails).toHaveLength(1);
    expect(plan(r, c, MON_3, new Map([['u1', 9]])).emails.map((e) => e.kind)).toEqual(['daily']);
  });

  it('orders entry watches, then packages, then saved searches, newest first within each', () => {
    const cs = changes(
      change('s1', '2026-11-23T05:00:00Z'),
      change('p1', '2026-11-23T03:00:00Z'),
      change('p2', '2026-11-23T04:00:00Z'),
      change('w1', '2026-11-23T01:00:00Z'),
    );
    const p = plan(
      [
        row('u1', 's1', { via: 'search:x', digest: 'daily' }),
        row('u1', 'p1', { via: 'pkg:npm/a', digest: 'daily' }),
        row('u1', 'p2', { via: 'pkg:npm/a', digest: 'daily' }),
        row('u1', 'w1', { digest: 'daily' }),
      ],
      cs,
      MON_3,
    );
    expect(p.emails[0]?.items.map((i) => i.changeId)).toEqual(['w1', 'p2', 'p1', 's1']);
  });
  it('counts queued rows it did not read as "more", and says which rows it covers', () => {
    const rows = Array.from({ length: 50 }, (_, i) =>
      row('u1', `c${i}`, { createdAt: `2026-11-23T01:${String(i).padStart(2, '0')}:00.000Z` }),
    );
    const cs = changes(...rows.map((r) => change(r.changeId, '2026-11-23T01:00:00Z')));
    const p = plan(rows, cs, MON_9, new Map(), new Map([['u1', { total: 130, watch: 120 }]]));
    expect(p.emails[0]?.items).toHaveLength(50);
    expect(p.emails[0]?.more).toBe(70); // an instant email counts the watch rows it did not read
    expect(p.emails[0]?.coversBefore).toEqual({
      cls: 0,
      createdAt: '2026-11-23T01:00:00.000Z',
      changeId: 'c0',
      watchOnly: true,
    });
    const digest = plan(
      rows.map((r) => ({ ...r, alertInstant: 0, digest: 'daily' })),
      cs,
      MON_3,
      new Map(),
      new Map([['u1', { total: 130, watch: 120 }]]),
    );
    expect(digest.emails[0]?.more).toBe(80);
    expect(digest.emails[0]?.coversBefore?.watchOnly).toBe(false);
  });
});

describe('plan: "and N more" only for a whole window', () => {
  const two = [row('u1', 'a'), row('u1', 'b')];
  const cs = changes(change('a', '2026-11-23T01:00:00Z'), change('b', '2026-11-23T02:00:00Z'));
  it("counts and covers the unread rows when the user's window was fully loaded", () => {
    const p = plan(two, cs, MON_9, new Map(), new Map([['u1', { total: 9, watch: 9, complete: true }]]));
    expect(p.emails[0]?.more).toBe(7);
    expect(p.emails[0]?.coversBefore).toBeDefined();
  });
  it('sends only the loaded rows and leaves the rest queued when the global limit cut the window short', () => {
    const p = plan(two, cs, MON_9, new Map(), new Map([['u1', { total: 9, watch: 9, complete: false }]]));
    expect(p.emails[0]?.more).toBe(0);
    expect(p.emails[0]?.coversBefore).toBeUndefined();
    expect(p.emails[0]?.items).toHaveLength(2);
  });
});
