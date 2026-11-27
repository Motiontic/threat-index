import { EMAIL_DAILY_CAP, utcDay } from '@ti/core/budget';
import { emailIdempotencyKey } from '@ti/core/email';
import type { Ecosystem } from '@ti/core/packages';
import { signUnsubscribeToken, UNSUBSCRIBE_PATH, type UnsubscribeScope } from '@ti/core/unsubscribe';
import { comparerFor } from '@ti/core/versions';
import { type Change, collect } from './collect';
import type { Deps, Env, NotifyMessage } from './env';
import {
  ALERT_DAILY_CAP,
  D1_CHUNK,
  DAY_MS,
  DIGEST_HOUR_UTC,
  MAX_FIXED_LISTED,
  MAX_NOTICE_EVENTS,
  MAX_QUEUE_ROWS,
  NOTICE_GAP_MS,
  NOTICE_MIN_AGE_MS,
  QUEUE_TTL_DAYS,
  SEND_GAP_MS,
  SENT_TTL_DAYS,
  WATCH_EVENT_TTL_DAYS,
} from './limits';
import { loadDocs, matchAndQueue } from './match';
import { type PlannedEmail, plan, type QueueRow } from './plan';
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

async function loadQueue(env: Env): Promise<QueueRow[]> {
  const rows = (
    await env.DB_USERS.prepare(
      `SELECT q.user_id, q.change_id, q.via, q.created_at, u.email, u.alert_instant, u.digest, u.digest_weekday,
              u.email_suppressed, u.deleted_at
       FROM alert_queue q JOIN users u ON u.id = q.user_id ORDER BY q.created_at, q.user_id, q.change_id LIMIT ?1`,
    )
      .bind(MAX_QUEUE_ROWS)
      .all<{
        user_id: string;
        change_id: string;
        via: string;
        created_at: string;
        email: string | null;
        alert_instant: number;
        digest: string;
        digest_weekday: number;
        email_suppressed: number;
        deleted_at: string | null;
      }>()
  ).results;
  return rows.map((r) => ({
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
  }));
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

/** Instant emails each user got since 00:00 UTC: distinct `alerts_sent.sent_at` values (one per email). */
async function loadInstantCounts(env: Env, runAt: Date): Promise<Map<string, number>> {
  const since = `${utcDay(runAt)}T00:00:00.000Z`;
  const rows = (
    await env.DB_USERS.prepare(
      'SELECT user_id, COUNT(DISTINCT sent_at) AS n FROM alerts_sent WHERE sent_at >= ?1 GROUP BY user_id',
    )
      .bind(since)
      .all<{ user_id: string; n: number }>()
  ).results;
  return new Map(rows.map((r) => [r.user_id, r.n]));
}

/** Package, fixed versions and our own name for each package-watch item: `${vulnKey}\0${ecosystem}/${name}` → info. */
async function loadPackageInfo(
  env: Env,
  items: { key: string; via: string }[],
): Promise<Map<string, PackageInfo>> {
  const out = new Map<string, PackageInfo>();
  const wanted = items.filter((i) => i.via.startsWith('pkg:'));
  if (wanted.length === 0) return out;
  const keys = [...new Set(wanted.map((i) => i.key))];
  const names = [...new Set(wanted.map((i) => i.via.slice(4).split('/').slice(1).join('/')))];
  const rows: { ecosystem: string; name: string; vuln_key: string; fixed: string | null }[] = [];
  for (const kPart of chunksOf(keys, D1_CHUNK / 2))
    for (const nPart of chunksOf(names, D1_CHUNK / 2))
      rows.push(
        ...(
          await env.DB_ADVISORIES.prepare(
            `SELECT ecosystem, name, vuln_key, fixed FROM affected
             WHERE vuln_key IN (${marks(kPart.length)}) AND name IN (${Array.from({ length: nPart.length }, (_, i) => `?${kPart.length + i + 1}`).join(',')})`,
          )
            .bind(...kPart, ...nPart)
            .all<{ ecosystem: string; name: string; vuln_key: string; fixed: string | null }>()
        ).results,
      );
  for (const w of wanted) {
    const slash = w.via.indexOf('/');
    const eco = w.via.slice(4, slash);
    const name = w.via.slice(slash + 1);
    const mine = rows.filter(
      (r) =>
        r.vuln_key === w.key && r.name === name && (r.ecosystem === eco || r.ecosystem.startsWith(`${eco}:`)),
    );
    const first = mine[0];
    const stored = [...new Set(mine.map((r) => r.fixed).filter((f): f is string => f !== null && f !== ''))];
    const cmp = first ? comparerFor(first.ecosystem as Ecosystem) : null;
    const ordered =
      cmp && stored.every((v) => cmp.valid(v)) ? [...stored].sort((a, b) => cmp.compare(a, b)) : stored;
    out.set(`${w.key}\0${w.via}`, {
      label: first ? `${first.ecosystem}/${first.name}` : `${eco}/${name}`,
      subjectLabel: subjectPackage(eco, name),
      fixed: ordered.slice(0, MAX_FIXED_LISTED),
    });
  }
  return out;
}

const chunksOf = <T>(xs: T[], n: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
};

/**
 * "Your MTI watchlist was changed": one email per user with pending MCP changes whose oldest is at least 10
 * minutes old, at most one an hour. Sent even when alerts are off, to the account's own address only.
 */
async function sendWatchNotices(env: Env, d: Deps, runAt: Date): Promise<void> {
  const oldEnough = new Date(runAt.getTime() - NOTICE_MIN_AGE_MS).toISOString();
  const gap = new Date(runAt.getTime() - NOTICE_GAP_MS).toISOString();
  const users = (
    await env.DB_USERS.prepare(
      `SELECT u.id, u.email FROM users u
       WHERE u.email_suppressed = 0 AND u.deleted_at IS NULL AND u.email != ''
         AND (SELECT MIN(at) FROM watch_events e WHERE e.user_id = u.id AND e.notified_at IS NULL) <= ?1
         AND NOT EXISTS (SELECT 1 FROM watch_events e WHERE e.user_id = u.id AND e.notified_at > ?2)
       ORDER BY u.id LIMIT ?3`,
    )
      .bind(oldEnough, gap, MAX_EMAILS_FOR_NOTICES)
      .all<{ id: string; email: string }>()
  ).results;
  if (users.length === 0) return;
  const out: Outgoing[] = [];
  for (const u of users) {
    const events = (
      await env.DB_USERS.prepare(
        `SELECT id, at, action, target, client_host FROM watch_events
         WHERE user_id = ?1 AND notified_at IS NULL ORDER BY at, id LIMIT ?2`,
      )
        .bind(u.id, MAX_NOTICE_EVENTS)
        .all<{ id: string; at: string; action: string; target: string; client_host: string | null }>()
    ).results;
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
const MAX_EMAILS_FOR_NOTICES = 20;

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

  // 1–2. Collect and match.
  const got = await collect(env, runAt);
  if (got.backlog) console.log(JSON.stringify({ event: 'notify.backlog', read: got.forwardCount }));
  const queued = await matchAndQueue(env, got.changes, got.cursor, runAt);

  // 3. Plan.
  const rows = await loadQueue(env);
  const changes = await loadChanges(env, [...new Set(rows.map((r) => r.changeId))]);
  const { emails, drop } = plan(rows, changes, runAt, await loadInstantCounts(env, runAt));
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
          appBase: env.APP_BASE,
          unsubscribeUrl,
          items: e.items.map((i) => {
            const doc = docs.get(i.change.entity_key);
            return {
              change: i.change,
              title: doc?.title ?? i.change.entity_key,
              company: i.change.kind === 'breach_notice',
              ...(i.via.startsWith('pkg:') ? { pkg: pkgInfo.get(`${i.change.entity_key}\0${i.via}`) } : {}),
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
      summary = await sendAll(env, d, runAt, out, SEND_GAP_MS, ALERT_DAILY_CAP);
    }
  }

  // 6. Prune on the digest run.
  if (runAt.getUTCHours() === DIGEST_HOUR_UTC) await prune(env, runAt);

  console.log(
    JSON.stringify({
      event: 'notify.run',
      changes: got.changes.length,
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
