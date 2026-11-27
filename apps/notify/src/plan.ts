import type { EmailKind } from '@ti/core/email';
import type { Change } from './collect';
import {
  DIGEST_HOUR_UTC,
  MAX_EMAILS_PER_RUN,
  MAX_INSTANT_PER_USER_PER_DAY,
  MAX_ITEMS_PER_EMAIL,
} from './limits';

export interface QueueRow {
  userId: string;
  changeId: string;
  via: string; // 'watch' | 'pkg:<ecosystem>/<name>' | 'search:<id>'
  createdAt: string;
  email: string;
  alertInstant: number;
  digest: string; // 'daily' | 'weekly' | 'off'
  digestWeekday: number;
  suppressed: number;
  deleted: string | null;
}

/** What a user has queued in all, read next to their (at most 50) newest rows. */
export interface Backlog {
  /** All the user's queued rows. */
  total: number;
  /** Those that are entry or package watches (the rows an instant email covers). */
  watch: number;
}

export interface PlanItem {
  changeId: string;
  via: string;
  change: Change;
}

export interface PlannedEmail {
  userId: string;
  email: string;
  kind: EmailKind;
  /** 0 = has instant items, 1 = daily digest, 2 = weekly digest. */
  priority: number;
  oldestQueued: string;
  items: PlanItem[];
  /** Loaded rows past the item cap: counted in `more`, deleted with the email. */
  hidden: PlanItem[];
  /** Queued rows this email covers but does not list: "and N more updates on your watchlist". */
  more: number;
  /** When `more > 0`: queued rows ranking after this one (class, then newest first) are covered too, and deleted with it. */
  coversBefore?: { cls: number; createdAt: string; changeId: string; watchOnly: boolean };
}

export interface Plan {
  emails: PlannedEmail[];
  /** Queue rows to delete: ineligible users, or changes that no longer exist. */
  drop: { userId: string; changeId: string }[];
}

export function digestDue(row: Pick<QueueRow, 'digest' | 'digestWeekday'>, runAt: Date): boolean {
  if (runAt.getUTCHours() !== DIGEST_HOUR_UTC) return false;
  if (row.digest === 'daily') return true;
  return row.digest === 'weekly' && runAt.getUTCDay() === row.digestWeekday;
}

/** Entry watches, then package watches, then saved searches. */
const classOf = (via: string): number => (via === 'watch' ? 0 : via.startsWith('pkg:') ? 1 : 2);

/** Entry-watch items, then package items, then saved-search items; newest first within each. */
const emailOrder = (a: PlanItem, b: PlanItem) =>
  classOf(a.via) - classOf(b.via) ||
  (a.change.at === b.change.at ? (a.changeId < b.changeId ? 1 : -1) : a.change.at < b.change.at ? 1 : -1);

/** True when `a` ranks after `b` in queue order: class first, then newest first. */
const rankAfter = (a: QueueRow, b: QueueRow): boolean =>
  classOf(a.via) !== classOf(b.via)
    ? classOf(a.via) > classOf(b.via)
    : a.createdAt !== b.createdAt
      ? a.createdAt < b.createdAt
      : a.changeId < b.changeId;

/** An entry watch or a package watch: the rows instant alerts are for. */
export const isWatchVia = (via: string): boolean => via === 'watch' || via.startsWith('pkg:');

/**
 * Pure: decides which emails go out this run. A user never gets two in one run.
 * `instantToday` is how many instant emails each user already got today (UTC); at 5 their items wait for the digest.
 */
export function plan(
  rows: QueueRow[],
  changes: ReadonlyMap<string, Change>,
  runAt: Date,
  instantToday: ReadonlyMap<string, number> = new Map(),
  backlog: ReadonlyMap<string, Backlog> = new Map(),
): Plan {
  const drop: Plan['drop'] = [];
  const byUser = new Map<
    string,
    { head: QueueRow; items: PlanItem[]; oldest: string; loaded: number; loadedWatch: number; edge: QueueRow }
  >();
  for (const r of rows) {
    const u = byUser.get(r.userId) ?? {
      head: r,
      items: [],
      oldest: r.createdAt,
      loaded: 0,
      loadedWatch: 0,
      edge: r,
    };
    byUser.set(r.userId, u);
    u.loaded++;
    if (classOf(r.via) < 2) u.loadedWatch++;
    // The last loaded row in class order: queued rows ranking after it were not read.
    if (rankAfter(r, u.edge)) u.edge = r;
    if (r.suppressed !== 0 || r.deleted !== null || r.email === '') {
      drop.push({ userId: r.userId, changeId: r.changeId });
      continue;
    }
    const change = changes.get(r.changeId);
    if (!change) {
      drop.push({ userId: r.userId, changeId: r.changeId });
      continue;
    }
    u.items.push({ changeId: r.changeId, via: r.via, change });
    if (r.createdAt < u.oldest) u.oldest = r.createdAt;
  }

  const emails: PlannedEmail[] = [];
  for (const [userId, u] of byUser) {
    if (u.items.length === 0) continue;
    const instantOk =
      u.head.alertInstant === 1 && (instantToday.get(userId) ?? 0) < MAX_INSTANT_PER_USER_PER_DAY;
    const instant = instantOk ? u.items.filter((i) => isWatchVia(i.via)) : [];
    let kind: EmailKind;
    let items: PlanItem[];
    if (digestDue(u.head, runAt)) {
      kind = u.head.digest === 'weekly' ? 'weekly' : 'daily';
      items = u.items;
    } else if (instant.length > 0) {
      kind = 'instant';
      items = instant;
    } else continue;
    const sorted = [...items].sort(emailOrder);
    const shown = sorted.slice(0, MAX_ITEMS_PER_EMAIL);
    const b = backlog.get(userId);
    const watchOnly = kind === 'instant';
    // Rows the email covers without listing: loaded ones past the 50, and queued ones that were not read at all.
    const unread = b ? Math.max(0, watchOnly ? b.watch - u.loadedWatch : b.total - u.loaded) : 0;
    const more = sorted.length - shown.length + unread;
    emails.push({
      userId,
      email: u.head.email,
      kind,
      priority: instant.length > 0 ? 0 : kind === 'daily' ? 1 : 2,
      oldestQueued: u.oldest,
      items: shown,
      hidden: sorted.slice(MAX_ITEMS_PER_EMAIL),
      more,
      ...(unread > 0
        ? {
            coversBefore: {
              cls: classOf(u.edge.via),
              createdAt: u.edge.createdAt,
              changeId: u.edge.changeId,
              watchOnly,
            },
          }
        : {}),
    });
  }
  emails.sort(
    (a, b) =>
      a.priority - b.priority ||
      (a.oldestQueued < b.oldestQueued ? -1 : a.oldestQueued > b.oldestQueued ? 1 : 0) ||
      (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0),
  );
  return { emails: emails.slice(0, MAX_EMAILS_PER_RUN), drop };
}
