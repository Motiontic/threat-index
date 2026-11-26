/** How long a deleted user stays refused on MCP: past any token that was issued before the deletion. */
export const DELETED_BLOCK_DAYS = 30;

/**
 * Removes every row that belongs to one user, in one batch, and blocks the user on MCP. Used by
 * `DELETE /v1/me` and the Clerk `user.deleted` webhook.
 *
 * Covers every ti_users table that holds the user: `watch`, `watch_packages`, `package_usage`,
 * `saved_searches`, `alert_queue`, `alerts_sent` (all by `user_id`) and `users` (by `id`). `email_log`
 * (daily counters) and `webhook_events` (svix ids) hold no user data. A new per-user table must be added here.
 *
 * The same batch inserts an `mcp_blocks` row (kind 'user', reason 'deleted', 30 days), so an unexpired OAuth
 * token of the deleted user stops working on MCP at once. That row holds only the Clerk user id. An existing block is never shortened.
 */
export async function deleteUserData(db: D1Database, userId: string, now: Date = new Date()): Promise<void> {
  const expires = new Date(now.getTime() + DELETED_BLOCK_DAYS * 86_400_000).toISOString();
  await db.batch(
    ['watch', 'watch_packages', 'package_usage', 'saved_searches', 'alert_queue', 'alerts_sent']
      .map((t) => db.prepare(`DELETE FROM ${t} WHERE user_id = ?1`).bind(userId))
      .concat(db.prepare('DELETE FROM users WHERE id = ?1').bind(userId))
      .concat(
        db
          .prepare(
            `INSERT INTO mcp_blocks (kind, id, reason, created_at, expires_at) VALUES ('user', ?1, 'deleted', ?2, ?3)
             ON CONFLICT (kind, id) DO UPDATE SET expires_at = CASE
               WHEN mcp_blocks.expires_at IS NULL THEN NULL
               WHEN mcp_blocks.expires_at > excluded.expires_at THEN mcp_blocks.expires_at
               ELSE excluded.expires_at END`,
          )
          .bind(userId, now.toISOString(), expires),
      ),
  );
}
