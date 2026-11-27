import { EMAIL_DAILY_CAP, utcDay } from '@ti/core/budget';
import { emailIdempotencyKey } from '@ti/core/email';
import type { Ecosystem } from '@ti/core/packages';
import { signUnsubscribeToken, UNSUBSCRIBE_PATH, type UnsubscribeScope } from '@ti/core/unsubscribe';
import { comparerFor } from '@ti/core/versions';
import { type Change, type Collected, type Cursor, collect } from './collect';
import type { Deps, Env, NotifyMessage } from './env';
import {
  ALERT_DAILY_CAP,
  D1_CHUNK,
  DAY_MS,
  DIGEST_HOUR_UTC,
  HOUR_MS,
  INSTANT_COUNT_TTL_DAYS,
  MAX_CHANGES_PER_RUN,
  MAX_FIXED_LISTED,
  MAX_NOTICE_EVENTS,
  MAX_PAGES_PER_RUN,
  MAX_QUEUE_READ_PER_USER,
  MAX_QUEUE_ROWS,
  NOTICE_DAILY_CAP,
  NOTICE_GAP_MS,
  NOTICE_MIN_AGE_MS,
  NOTICE_PER_USER_PER_DAY,
  QUEUE_TTL_DAYS,
  RUN_TIME_BUDGET_MS,
  SEND_GAP_MS,
  SENT_TTL_DAYS,
  WATCH_EVENT_TTL_DAYS,
} from './limits';
import { loadDocs, matchAndQueue } from './match';
import { type Backlog, type PlannedEmail, plan, type QueueRow } from './plan';
import { type PackageInfo, renderEmail, renderWatchNotice, subjectPackage } from './render';
import { type Outgoing, remainingToday, sendAll } from './send';

export type { Env, NotifyMessage } from './env';

const defaultDeps: Deps = {
  fetch: (input, init) => globalThis.fetch(input, init),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => Date.now(),
};

const marks = (n: number) => Array.from({ length: n }, (_, i) => `?${i + 1}`).join(',');
function chunks<T>(xs: T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += D1_CHUNK) out.push(xs.slice(i, i + D1_CHUNK));
  return out;
}

/**
 * The queue, per user: at most each user's MAX_QUEUE_READ_PER_USER newest rows (a window function), so one user's
 * backlog can't fill the read for everyone. `backlog` has each user's full counts for the "and N more" line.
 */
async function loadQueue(env: Env): Promise<{ rows: QueueRow[]; backlog: Map<string, Backlog> }> {
  const rows = (
    await env.DB_USERS.prepare(
      `SELECT r.user_id, r.change_id, r.via, r.created_at, r.total, r.total_watch,
              u.email, u.alert_instant, u.digest, u.digest_weekday, u.email_suppressed, u.deleted_at
       FROM (
         SELECT q.user_id, q.change_id, q.via, q.created_at,
                ROW_NUMBER() OVER (PARTITION BY q.user_id ORDER BY CASE WHEN q.via = 'watch' THEN 0 WHEN q.via LIKE 'pkg:%' THEN 1 ELSE 2 END, q.created_at DESC, q.change_id DESC) AS rn,
                COUNT(*) OVER (PARTITION BY q.user_id) AS total,
                SUM(CASE WHEN q.via = 'watch' OR q.via LIKE 'pkg:%' THEN 1 ELSE 0 END) OVER (PARTITION BY q.user_id) AS total_watch
         FROM alert_queue q
       ) r JOIN users u ON u.id = r.user_id
       WHERE r.rn <= ?2 ORDER BY r.created_at, r.user_id, r.change_id LIMIT ?1`,
    )
      .bind(MAX_QUEUE_ROWS, MAX_QUEUE_READ_PER_USER)
      .all<{
        user_id: string;
        change_id: string;
        via: string;
        created_at: string;
        total: number;
        total_watch: number;
        email: string | null;
        alert_instant: number;
        digest: string;
        digest_weekday: number;
        email_suppressed: number;
        deleted_at: string | null;
      }>()
  ).results;
  const backlog = new Map<string, Backlog>();
  const loaded = new Map<string, number>();
  for (const r of rows) {
    loaded.set(r.user_id, (loaded.get(r.user_id) ?? 0) + 1);
    backlog.set(r.user_id, { total: r.total, watch: r.total_watch });
  }
  // A window is whole when every row the per-user read allows was loaded; the global limit can cut it short.
  for (const [userId, b] of backlog)
    b.complete = (loaded.get(userId) ?? 0) >= Math.min(b.total, MAX_QUEUE_READ_PER_USER);
  return {
    backlog,
    rows: rows.map((r) => ({
      userId: r.user_id,
      changeId: r.change_id,
      via: r.via,
      createdAt: r.created_at,
      email: r.email ?? '',
      alertInstant: r.alert_instant,
      digest: r.digest,
      digestWeekday: r.digest_weekday,
      suppressed: r.email_suppressed,
      deleted: r.deleted_at,
    })),
  };
}

async function loadChanges(env: Env, ids: string[]): Promise<Map<string, Change>> {
  const out = new Map<string, Change>();
  for (const part of chunks(ids)) {
    const rows = (
      await env.DB_SIGNALS.prepare(
        `SELECT id, entity_key, kind, old, new, at, source FROM changes WHERE id IN (${marks(part.length)})`,
      )
        .bind(...part)
        .all<Change>()
    ).results;
    for (const c of rows) out.set(c.id, c);
  }
  return out;
}

async function loadLabels(env: Env, userIds: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>(); // `${userId}:${searchId}` → label
  for (const part of chunks(userIds)) {
    const rows = (
      await env.DB_USERS.prepare(
        `SELECT user_id, id, label FROM saved_searches WHERE user_id IN (${marks(part.length)})`,
      )
        .bind(...part)
        .all<{ user_id: string; id: string; label: string }>()
    ).results;
    for (const r of rows) out.set(`${r.user_id}:${r.id}`, r.label);
  }
  return out;
}

function scopeFor(e: PlannedEmail): { scope: UnsubscribeScope; item?: string } {
  if (e.kind !== 'instant') return { scope: 'digest' };
  // Package-only instant emails (one package) switch off that package; mixed emails use `all`.
  if (e.items.every((i) => i.via.startsWith('pkg:'))) {
    const pkgs = new Set(e.items.map((i) => i.via.slice(4)));
    const only = pkgs.size === 1 ? [...pkgs][0] : undefined;
    return only && only.length <= 256 ? { scope: 'package', item: only } : { scope: 'all' };
  }
  if (e.items.some((i) => i.via.startsWith('pkg:'))) return { scope: 'all' };
  const keys = new Set(e.items.map((i) => i.change.entity_key));
  const only = keys.size === 1 ? [...keys][0] : undefined;
  return only ? { scope: 'watch', item: only } : { scope: 'all' };
}

/** Instant emails each user already got today (UTC), from `instant_counts`. */
async function loadInstantCounts(env: Env, runAt: Date): Promise<Map<string, number>> {
  const rows = (
    await env.DB_USERS.prepare('SELECT user_id, n FROM instant_counts WHERE day = ?1')
      .bind(utcDay(runAt))
      .all<{ user_id: string; n: number }>()
  ).results;
  return new Map(rows.map((r) => [r.user_id, r.n]));
}

/** The package named by a `pkg:<ecosystem>/<name>` queue row. */
function viaPackage(via: string): { eco: string; name: string } {
  const slash = via.indexOf('/');
  return { eco: via.slice(4, slash), name: via.slice(slash + 1) };
}

/** What an alert says about a package when its fixed versions can't be read. */
function unknownInfo(via: string): PackageInfo {
  const { eco, name } = viaPackage(via);
  return { label: `${eco}/${name}`, subjectLabel: subjectPackage(eco, name), fixed: [], unknownFixed: true };
}

/** `+name` keeps SQLite on `affected_by_vuln` (vuln_key, then the ecosystem range) rather than `affected_by_name`. */
export const FIXED_SQL = `SELECT DISTINCT fixed FROM affected
  WHERE vuln_key = ?1 AND +name = ?3
    AND (ecosystem = ?2 OR (ecosystem > ?2 || ':' AND ecosystem < ?2 || ';'))
    AND fixed IS NOT NULL AND fixed != '' ORDER BY fixed LIMIT ?4`;

/**
 * Package and up to MAX_FIXED_LISTED distinct fixed versions for each package-watch item:
 * `${vulnKey}\0${ecosystem}/${name}` → info. One bounded statement per item (`SELECT DISTINCT fixed … LIMIT 5`
 * for that vuln, base ecosystem and name), batched. Never reads every `affected` row of a vuln. A failure gives an
 * empty map: the caller falls back to `unknownInfo`, so nothing stops a send.
 */
async function loadPackageInfo(
  env: Env,
  items: { key: string; via: string }[],
): Promise<Map<string, PackageInfo>> {
  const out = new Map<string, PackageInfo>();
  try {
    const wanted = [
      ...new Map(
        items.filter((i) => i.via.startsWith('pkg:')).map((i) => [`${i.key}\0${i.via}`, i] as const),
      ).values(),
    ];
    for (const part of chunksOf(wanted, D1_CHUNK)) {
      const results = await env.DB_ADVISORIES.batch<{ fixed: string | null }>(
        part.map((w) => {
          const { eco, name } = viaPackage(w.via);
          return env.DB_ADVISORIES.prepare(FIXED_SQL).bind(w.key, eco, name, MAX_FIXED_LISTED + 1);
        }),
      );
      part.forEach((w, n) => {
        const { eco, name } = viaPackage(w.via);
        const stored = (results[n]?.results ?? []).map((r) => r.fixed).filter((f): f is string => !!f);
        const cmp = comparerFor(eco as Ecosystem);
        const ordered =
          cmp && stored.every((v) => cmp.valid(v)) ? [...stored].sort((a, b) => cmp.compare(a, b)) : stored;
        out.set(`${w.key}\0${w.via}`, {
          label: `${eco}/${name}`,
          subjectLabel: subjectPackage(eco, name),
          fixed: ordered.slice(0, MAX_FIXED_LISTED),
          ...(stored.length > MAX_FIXED_LISTED ? { moreFixed: true } : {}),
        });
      });
    }
  } catch (e) {
    console.log(
      JSON.stringify({ event: 'notify.package_info_failed', error: e instanceof Error ? e.name : 'error' }),
    );
    return new Map();
  }
  return out;
}

const chunksOf = <T>(xs: T[], n: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
};

/** Watchlist change notices sent or dry-run today (UTC), from `email_sends`. */
async function noticesToday(env: Env, runAt: Date): Promise<number> {
  const row = await env.DB_USERS.prepare(
    "SELECT COUNT(*) AS n FROM email_sends WHERE kind = 'watch_notice' AND status IN ('sent','dry_run') AND created_at >= ?1",
  )
    .bind(`${utcDay(runAt)}T00:00:00.000Z`)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

/**
 * "Your MTI watchlist was changed": one email per user with pending MCP changes whose oldest is at least 10
 * minutes old, at most one an hour and two a day per user, and NOTICE_DAILY_CAP a day in all. Users are picked:
 * pending removals and digest changes first, then fewest notices in 24 hours, then oldest pending event (driven
 * from the `watch_events_pending` index). Events not mailed carry over to the
 * next run. Sent even when alerts are off, to the account's own address only.
 */
async function sendWatchNotices(env: Env, d: Deps, runAt: Date): Promise<void> {
  const room = NOTICE_DAILY_CAP - (await noticesToday(env, runAt));
  if (room <= 0) return;
  const oldEnough = new Date(runAt.getTime() - NOTICE_MIN_AGE_MS).toISOString();
  const gap = new Date(runAt.getTime() - NOTICE_GAP_MS).toISOString();
  const dayStart = `${utcDay(runAt)}T00:00:00.000Z`;
  const cut24 = new Date(runAt.getTime() - DAY_MS).toISOString();
  // Driven from the pending events (index `watch_events_pending`). A pending removal or digest change goes
  // first, then the users with the fewest notices in the last 24 hours, then the oldest pending event.
  const users = (
    await env.DB_USERS.prepare(
      `SELECT p.user_id AS id, u.email FROM (
         SELECT user_id, MIN(at) AS oldest, MAX(action IN ('remove', 'digest_on')) AS urgent
         FROM watch_events WHERE notified_at IS NULL
         GROUP BY user_id HAVING MIN(at) <= ?1
       ) p JOIN users u ON u.id = p.user_id
       WHERE u.email_suppressed = 0 AND u.deleted_at IS NULL AND u.email != ''
         AND NOT EXISTS (SELECT 1 FROM watch_events e WHERE e.user_id = p.user_id AND e.notified_at > ?2)
         AND (SELECT COUNT(DISTINCT e.notified_at) FROM watch_events e WHERE e.user_id = p.user_id AND e.notified_at >= ?3) < ?4
       ORDER BY p.urgent DESC,
         (SELECT COUNT(DISTINCT e.notified_at) FROM watch_events e WHERE e.user_id = p.user_id AND e.notified_at >= ?6),
         p.oldest, p.user_id LIMIT ?5`,
    )
      .bind(oldEnough, gap, dayStart, NOTICE_PER_USER_PER_DAY, room, cut24)
      .all<{ id: string; email: string }>()
  ).results;
  if (users.length === 0) return;
  // One read for every chosen user's events (at most MAX_NOTICE_EVENTS each, oldest first).
  const eventRows = (
    await env.DB_USERS.prepare(
      `SELECT user_id, id, at, action, target, client_host FROM (
         SELECT user_id, id, at, action, target, client_host,
                ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY at, id) AS rn
         FROM watch_events WHERE notified_at IS NULL AND user_id IN (SELECT value FROM json_each(?1))
       ) WHERE rn <= ?2 ORDER BY user_id, at, id`,
    )
      .bind(JSON.stringify(users.map((u) => u.id)), MAX_NOTICE_EVENTS)
      .all<{
        user_id: string;
        id: string;
        at: string;
        action: string;
        target: string;
        client_host: string | null;
      }>()
  ).results;
  const eventsOf = new Map<string, typeof eventRows>();
  for (const e of eventRows) eventsOf.set(e.user_id, [...(eventsOf.get(e.user_id) ?? []), e]);
  const out: Outgoing[] = [];
  for (const u of users) {
    const events = eventsOf.get(u.id) ?? [];
    if (events.length === 0) continue;
    const ids = events.map((e) => e.id);
    out.push({
      planned: {
        userId: u.id,
        email: u.email,
        kind: 'watch_notice',
        priority: 0,
        oldestQueued: events[0]?.at ?? '',
        items: [],
        hidden: [],
        more: 0,
      },
      key: await emailIdempotencyKey(u.id, 'watch_notice', ids),
      rendered: renderWatchNotice(
        events.map((e) => ({ at: e.at, action: e.action, target: e.target, clientHost: e.client_host })),
        env.APP_BASE,
      ),
      unsubscribeUrl: null,
      eventIds: ids,
    });
  }
  const summary = await sendAll(env, d, runAt, out, SEND_GAP_MS, EMAIL_DAILY_CAP);
  console.log(JSON.stringify({ event: 'notify.notices', users: out.length, ...summary }));
}

async function prune(env: Env, runAt: Date): Promise<void> {
  const ago = (days: number) => new Date(runAt.getTime() - days * DAY_MS);
  const sentCut = ago(SENT_TTL_DAYS);
  await env.DB_USERS.batch([
    env.DB_USERS.prepare('DELETE FROM alert_queue WHERE created_at < ?1').bind(
      ago(QUEUE_TTL_DAYS).toISOString(),
    ),
    env.DB_USERS.prepare('DELETE FROM alerts_sent WHERE sent_at < ?1').bind(sentCut.toISOString()),
    env.DB_USERS.prepare('DELETE FROM email_sends WHERE created_at < ?1').bind(sentCut.toISOString()),
    env.DB_USERS.prepare('DELETE FROM email_log WHERE day < ?1').bind(utcDay(sentCut)),
    env.DB_USERS.prepare('DELETE FROM instant_counts WHERE day < ?1').bind(
      utcDay(ago(INSTANT_COUNT_TTL_DAYS)),
    ),
    env.DB_USERS.prepare('DELETE FROM watch_events WHERE at < ?1').bind(
      ago(WATCH_EVENT_TTL_DAYS).toISOString(),
    ),
  ]);
}

/** One notify run, decided by `runAt` (the cron time), not the wall clock. */
export async function runNotify(env: Env, runAt: Date, deps: Partial<Deps> = {}): Promise<void> {
  const d: Deps = { ...defaultDeps, ...deps };

  // 0. Watchlist change notices go first: they share the daily cap and alerts leave room for them.
  try {
    await sendWatchNotices(env, d, runAt);
  } catch (e) {
    console.log(
      JSON.stringify({ event: 'notify.notice_failed', error: e instanceof Error ? e.name : 'error' }),
    );
  }

  // 1–2. Collect and match, a page at a time. Each page saves its cursor with its queue rows, so a later
  // failure keeps the earlier pages. Only the first page reads the late window.
  const startedAt = d.now();
  let pages = 0;
  let read = 0;
  let readAll = 0;
  let queued = 0;
  let cursor: Cursor | null = null;
  let more = false;
  for (;;) {
    const got: Collected = await collect(env, runAt, cursor ? { cursor } : undefined);
    pages++;
    read += got.forwardCount;
    readAll += got.changes.length;
    cursor = got.cursor;
    if (got.backlog) console.log(JSON.stringify({ event: 'notify.backlog', read: got.forwardCount }));
    queued += await matchAndQueue(env, got.changes, got.cursor, runAt);
    if (got.forwardCount < MAX_CHANGES_PER_RUN) break;
    if (pages >= MAX_PAGES_PER_RUN || d.now() - startedAt >= RUN_TIME_BUDGET_MS) {
      more = true;
      break;
    }
  }
  if (more && cursor) {
    const lagHours = Math.round(((runAt.getTime() - Date.parse(cursor.at)) / HOUR_MS) * 10) / 10;
    console.log(JSON.stringify({ event: 'notify.behind', pages, read, lagHours }));
  }

  // 3. Plan.
  const { rows, backlog } = await loadQueue(env);
  const changes = await loadChanges(env, [...new Set(rows.map((r) => r.changeId))]);
  const { emails, drop } = plan(rows, changes, runAt, await loadInstantCounts(env, runAt), backlog);
  for (let i = 0; i < drop.length; i += D1_CHUNK)
    await env.DB_USERS.batch(
      drop
        .slice(i, i + D1_CHUNK)
        .map((r) =>
          env.DB_USERS.prepare('DELETE FROM alert_queue WHERE user_id = ?1 AND change_id = ?2').bind(
            r.userId,
            r.changeId,
          ),
        ),
    );

  // 4–5. Render and send.
  let summary: { byKind: object; capReached: boolean; stopped: boolean } = {
    byKind: {},
    capReached: false,
    stopped: false,
  };
  if (emails.length > 0) {
    if (!env.UNSUBSCRIBE_SECRET) {
      console.log(JSON.stringify({ event: 'notify.no_unsubscribe_secret', pending: emails.length }));
    } else {
      const docs = await loadDocs(
        env,
        emails.flatMap((e) => e.items.map((i) => i.change)),
      );
      const labels = await loadLabels(env, [...new Set(emails.map((e) => e.userId))]);
      const pkgInfo = await loadPackageInfo(
        env,
        emails.flatMap((e) => e.items.map((i) => ({ key: i.change.entity_key, via: i.via }))),
      );
      const out: Outgoing[] = [];
      for (const e of emails) {
        const { scope, item } = scopeFor(e);
        const token = await signUnsubscribeToken(env.UNSUBSCRIBE_SECRET, {
          userId: e.userId,
          scope,
          ...(item === undefined ? {} : { item }),
          issuedAt: runAt.getTime(),
        });
        const unsubscribeUrl = `${env.API_BASE.replace(/\/+$/, '')}${UNSUBSCRIBE_PATH}?t=${token}`;
        const rendered = renderEmail({
          kind: e.kind,
          more: e.more,
          appBase: env.APP_BASE,
          unsubscribeUrl,
          items: e.items.map((i) => {
            const doc = docs.get(i.change.entity_key);
            return {
              change: i.change,
              title: doc?.title ?? i.change.entity_key,
              company: i.change.kind === 'breach_notice',
              ...(i.via.startsWith('pkg:')
                ? { pkg: pkgInfo.get(`${i.change.entity_key}\0${i.via}`) ?? unknownInfo(i.via) }
                : {}),
              group: i.via.startsWith('search:')
                ? (labels.get(`${e.userId}:${i.via.slice(7)}`) ?? 'a saved search')
                : null,
            };
          }),
        });
        const key = await emailIdempotencyKey(
          e.userId,
          e.kind,
          e.items.map((i) => i.changeId),
        );
        out.push({ planned: e, key, rendered, unsubscribeUrl });
      }
      // Alerts get ALERT_DAILY_CAP of the day's sends; the notices sent today sit on top, so the total stays under 95.
      summary = await sendAll(
        env,
        d,
        runAt,
        out,
        SEND_GAP_MS,
        Math.min(EMAIL_DAILY_CAP, ALERT_DAILY_CAP + (await noticesToday(env, runAt))),
      );
    }
  }

  // 6. Prune on the digest run.
  if (runAt.getUTCHours() === DIGEST_HOUR_UTC) await prune(env, runAt);

  console.log(
    JSON.stringify({
      event: 'notify.run',
      pages,
      changes: readAll,
      queued,
      emails: summary.byKind,
      capReached: summary.capReached,
      stopped: summary.stopped,
      capLeft: await remainingToday(env, runAt),
    }),
  );
}

function parseMessage(body: unknown, nowMs: number): { at: number } | null {
  if (typeof body !== 'object' || body === null) return null;
  const m = body as Record<string, unknown>;
  if (m.kind !== 'run-finished') return null;
  if (typeof m.at !== 'number' || !Number.isFinite(m.at)) return null;
  if (Math.abs(m.at - nowMs) > 365 * DAY_MS) return null;
  return { at: m.at };
}

export async function consume(
  batch: MessageBatch<NotifyMessage>,
  env: Env,
  deps: Partial<Deps> = {},
): Promise<void> {
  for (const msg of batch.messages) {
    const parsed = parseMessage(msg.body, (deps.now ?? defaultDeps.now)());
    if (!parsed) {
      console.log(JSON.stringify({ event: 'notify.bad_message' }));
      msg.ack();
      continue;
    }
    try {
      await runNotify(env, new Date(parsed.at), deps);
      msg.ack();
    } catch (e) {
      console.log(
        JSON.stringify({ event: 'notify.run_failed', error: e instanceof Error ? e.name : 'error' }),
      );
      msg.retry({ delaySeconds: 300 });
    }
  }
}
