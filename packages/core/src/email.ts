/**
 * Shared email contract between the notify worker (sends) and anything that needs to name an email.
 * The unsubscribe token format lives in `./unsubscribe`, not here.
 */
export const EMAIL_KINDS = ['instant', 'daily', 'weekly', 'watch_notice'] as const;
export type EmailKind = (typeof EMAIL_KINDS)[number];

/**
 * Idempotency key for one email: `ti-<kind>-` + the first 40 hex chars of SHA-256 of
 * `userId\nkind\n<ids sorted, comma-joined>`. Order of `changeIds` does not matter, and the user ID
 * never appears in clear.
 */
export async function emailIdempotencyKey(
  userId: string,
  kind: EmailKind,
  changeIds: readonly string[],
): Promise<string> {
  const text = `${userId}\n${kind}\n${[...changeIds].sort().join(',')}`;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  const hex = [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `ti-${kind}-${hex.slice(0, 40)}`;
}
