/** Daily package quota for POST /v1/packages/check, kept in `package_usage` (ti_users). */

export const DAILY_PACKAGE_QUOTA = 20_000;
export type QuotaResult = { ok: true; used: number } | { ok: false; remaining: number; retryAfter: number };

const dayOf = (now: Date): string => now.toISOString().slice(0, 10);

/** Whole seconds until the next 00:00 UTC, at least 1. */
export function secondsToUtcMidnight(now: Date): number {
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

/**
 * Adds `count` and checks the limit in one statement, so parallel calls can't both pass. Throws on any D1
 * error; the route then answers 503 (the quota fails closed).
 */
export async function chargeQuota(
  db: D1Database,
  userId: string,
  count: number,
  now: Date,
): Promise<QuotaResult> {
  const day = dayOf(now);
  const res = await db
    .prepare(
      `INSERT INTO package_usage (user_id, day, packages, calls)
       SELECT ?1, ?2, ?3, 1 WHERE ?3 <= ?4
       ON CONFLICT (user_id, day) DO UPDATE
         SET packages = packages + excluded.packages, calls = calls + 1
         WHERE package_usage.packages + excluded.packages <= ?4
       RETURNING packages`,
    )
    .bind(userId, day, count, DAILY_PACKAGE_QUOTA)
    .all<{ packages: number }>();
  const row = res.results?.[0];
  if (row) return { ok: true, used: row.packages };
  let remaining = 0;
  try {
    const cur = await db
      .prepare('SELECT packages FROM package_usage WHERE user_id = ?1 AND day = ?2')
      .bind(userId, day)
      .first<{ packages: number }>();
    remaining = Math.max(0, DAILY_PACKAGE_QUOTA - (cur?.packages ?? 0));
  } catch {
    remaining = 0;
  }
  return { ok: false, remaining, retryAfter: secondsToUtcMidnight(now) };
}

/** Gives back a charge after a failed lookup. */
export async function refundQuota(db: D1Database, userId: string, count: number, now: Date): Promise<void> {
  await db
    .prepare('UPDATE package_usage SET packages = MAX(0, packages - ?3) WHERE user_id = ?1 AND day = ?2')
    .bind(userId, dayOf(now), count)
    .run();
}
