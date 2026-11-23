/**
 * Daily write budget meter. These are caps the project keeps for itself, not limits Cloudflare enforces
 * on a paid account: 100,000 D1 rows written a day (indexes count), with the first load stopping at 90,000.
 * Steady updates are always counted but never blocked.
 */
export const D1_DAILY_WRITE_LIMIT = 100_000;
export const FIRST_LOAD_DAILY_CAP = 90_000;
export const EMAIL_DAILY_CAP = 95; // Resend free plan: 100 a day

export type WritePriority = 'steady' | 'first-load';

export function utcDay(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export function secondsUntilUtcMidnight(now: Date = new Date()): number {
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

function checkCount(n: number, priority?: WritePriority): void {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(`write count must be a non-negative integer: ${n}`);
  if (priority === 'first-load' && n > FIRST_LOAD_DAILY_CAP) {
    // It could never fit under the cap, so it would be deferred forever.
    throw new RangeError(`first-load write of ${n} exceeds the daily cap of ${FIRST_LOAD_DAILY_CAP}`);
  }
}

/** Atomically reserves `n` writes for today. Returns false when a first-load batch must wait. */
export async function reserveWrites(
  db: D1Database,
  n: number,
  priority: WritePriority,
  now: Date = new Date(),
): Promise<boolean> {
  checkCount(n, priority);
  if (n === 0) return true;
  const day = utcDay(now);
  if (priority === 'steady') {
    await db
      .prepare(
        'INSERT INTO budget (day, d1_writes) VALUES (?1, ?2) ON CONFLICT (day) DO UPDATE SET d1_writes = d1_writes + excluded.d1_writes',
      )
      .bind(day, n)
      .run();
    return true;
  }
  await db.prepare('INSERT INTO budget (day) VALUES (?1) ON CONFLICT(day) DO NOTHING').bind(day).run();
  const res = await db
    .prepare('UPDATE budget SET d1_writes = d1_writes + ?1 WHERE day = ?2 AND d1_writes + ?1 <= ?3')
    .bind(n, day, FIRST_LOAD_DAILY_CAP)
    .run();
  return (res.meta.changes ?? 0) > 0;
}

/** Gives back `n` reserved writes for today's meter, never going below 0. */
export async function releaseWrites(db: D1Database, n: number, now: Date = new Date()): Promise<void> {
  checkCount(n);
  if (n === 0) return;
  await db
    .prepare('UPDATE budget SET d1_writes = MAX(0, d1_writes - ?1) WHERE day = ?2')
    .bind(n, utcDay(now))
    .run();
}

export interface BudgetUsage {
  day: string;
  d1Writes: number;
  firstLoadCap: number;
  dailyLimit: number;
  firstLoadRemaining: number;
}

/** Today's usage, for the watchdog and /ops. Read only; zeros when today has no row yet. */
export async function budgetUsage(db: D1Database, now: Date = new Date()): Promise<BudgetUsage> {
  const day = utcDay(now);
  const row = await db
    .prepare('SELECT d1_writes FROM budget WHERE day = ?1')
    .bind(day)
    .first<{ d1_writes: number }>();
  const d1Writes = row?.d1_writes ?? 0;
  return {
    day,
    d1Writes,
    firstLoadCap: FIRST_LOAD_DAILY_CAP,
    dailyLimit: D1_DAILY_WRITE_LIMIT,
    firstLoadRemaining: Math.max(0, FIRST_LOAD_DAILY_CAP - d1Writes),
  };
}
