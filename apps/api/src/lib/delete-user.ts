/** Removes every row that belongs to one user. Used by the Clerk `user.deleted` webhook. */
export async function deleteUserData(db: D1Database, userId: string): Promise<void> {
  await db.batch(
    ['watch', 'saved_searches', 'alert_queue', 'alerts_sent']
      .map((t) => db.prepare(`DELETE FROM ${t} WHERE user_id = ?1`).bind(userId))
      .concat(db.prepare('DELETE FROM users WHERE id = ?1').bind(userId)),
  );
}
