/**
 * Removes every row that belongs to one user, in one batch. Used by `DELETE /v1/me` and the Clerk
 * `user.deleted` webhook.
 *
 * Covers every ti_users table that holds the user: `watch`, `saved_searches`, `alert_queue`,
 * `alerts_sent` (all by `user_id`) and `users` (by `id`). `email_log` (daily counters) and
 * `webhook_events` (svix ids) hold no user data. A new per-user table must be added here.
 */
export async function deleteUserData(db: D1Database, userId: string): Promise<void> {
  await db.batch(
    ['watch', 'saved_searches', 'alert_queue', 'alerts_sent']
      .map((t) => db.prepare(`DELETE FROM ${t} WHERE user_id = ?1`).bind(userId))
      .concat(db.prepare('DELETE FROM users WHERE id = ?1').bind(userId)),
  );
}
