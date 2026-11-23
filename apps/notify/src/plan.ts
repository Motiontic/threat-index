import type { EmailKind } from '@ti/core/email';
import type { Change } from './collect';
import { DIGEST_HOUR_UTC, MAX_EMAILS_PER_RUN, MAX_ITEMS_PER_EMAIL } from './limits';

export interface QueueRow {
  userId: string;
  changeId: string;
  via: string; // 'watch' | 'search:<id>'
  createdAt: string;
  email: string;
  alertInstant: number;
  digest: string; // 'daily' | 'weekly' | 'off'
  digestWeekday: number;
  suppressed: number;
  deleted: string | null;
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

const newestFirst = (a: PlanItem, b: PlanItem) =>
  a.change.at === b.change.at ? (a.changeId < b.changeId ? 1 : -1) : a.change.at < b.change.at ? 1 : -1;

/** Pure: decides which emails go out this run. A user never gets two in one run. */
export function plan(rows: QueueRow[], changes: ReadonlyMap<string, Change>, runAt: Date): Plan {
  const drop: Plan['drop'] = [];
  const byUser = new Map<string, { head: QueueRow; items: PlanItem[]; oldest: string }>();
  for (const r of rows) {
    if (r.suppressed !== 0 || r.deleted !== null || r.email === '') {
      drop.push({ userId: r.userId, changeId: r.changeId });
      continue;
    }
    const change = changes.get(r.changeId);
    if (!change) {
      drop.push({ userId: r.userId, changeId: r.changeId });
      continue;
    }
    const u = byUser.get(r.userId) ?? { head: r, items: [], oldest: r.createdAt };
    u.items.push({ changeId: r.changeId, via: r.via, change });
    if (r.createdAt < u.oldest) u.oldest = r.createdAt;
    byUser.set(r.userId, u);
  }

  const emails: PlannedEmail[] = [];
  for (const [userId, u] of byUser) {
    const instant = u.head.alertInstant === 1 ? u.items.filter((i) => i.via === 'watch') : [];
    let kind: EmailKind;
    let items: PlanItem[];
    if (digestDue(u.head, runAt)) {
      kind = u.head.digest === 'weekly' ? 'weekly' : 'daily';
      items = u.items;
    } else if (instant.length > 0) {
      kind = 'instant';
      items = instant;
    } else continue;
    emails.push({
      userId,
      email: u.head.email,
      kind,
      priority: instant.length > 0 ? 0 : kind === 'daily' ? 1 : 2,
      oldestQueued: u.oldest,
      items: [...items].sort(newestFirst).slice(0, MAX_ITEMS_PER_EMAIL),
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
