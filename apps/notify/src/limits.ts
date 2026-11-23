export const MAX_CHANGES_PER_RUN = 500;
export const LATE_WINDOW_HOURS = 6;
export const FIRST_RUN_WINDOW_HOURS = 3;
export const MAX_ITEMS_PER_EMAIL = 50;
/** Keeps a run well under the subrequest limit. */
export const MAX_EMAILS_PER_RUN = 40;
/** Resend's default rate limit is 2 requests per second per team; 600 ms stays under it (figure not re-checked against the live docs). */
export const SEND_GAP_MS = 600;
export const DIGEST_HOUR_UTC = 3;
export const QUEUE_TTL_DAYS = 14;
export const SENT_TTL_DAYS = 30;
/** Bound values per `IN (…)`. */
export const D1_CHUNK = 90;
export const MAX_QUEUE_ROWS = 5000;
export const MAX_SAVED_SEARCHES = 5000;
export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;
