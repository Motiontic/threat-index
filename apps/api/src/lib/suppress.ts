const MAX_ADDRESSES = 50;

/** Marks users with these addresses as suppressed (bounce or complaint). Returns the rows changed. */
export async function suppressAddresses(db: D1Database, emails: string[]): Promise<number> {
  const unique = [...new Set(emails.map((e) => e.trim().toLowerCase()).filter(Boolean))].slice(
    0,
    MAX_ADDRESSES,
  );
  if (unique.length === 0) return 0;
  const results = await db.batch(
    unique.map((e) =>
      db
        .prepare('UPDATE users SET email_suppressed = 1 WHERE lower(email) = ?1 AND email_suppressed = 0')
        .bind(e),
    ),
  );
  return results.reduce((n, r) => n + (r.meta?.changes ?? 0), 0);
}
