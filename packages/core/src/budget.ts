/**
 * Free-plan budget meter. D1 allows 100,000 rows written per day (indexes count).
 * Steady updates are always counted but never blocked; the first load stops at 90,000.
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

/** Atomically reserves `n` writes for today. Returns false when a first-load batch must wait. */
export async function reserveWrites(
  db: D1Database,
  n: number,
  priority: WritePriority,
  now: Date = new Date(),
): Promise<boolean> {
  const day = utcDay(now);
  await db.prepare('INSERT INTO budget (day) VALUES (?1) ON CONFLICT(day) DO NOTHING').bind(day).run();
  if (priority === 'steady') {
    await db.prepare('UPDATE budget SET d1_writes = d1_writes + ?1 WHERE day = ?2').bind(n, day).run();
    return true;
  }
  const res = await db
    .prepare('UPDATE budget SET d1_writes = d1_writes + ?1 WHERE day = ?2 AND d1_writes + ?1 <= ?3')
    .bind(n, day, FIRST_LOAD_DAILY_CAP)
    .run();
  return (res.meta.changes ?? 0) > 0;
}
