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
/** Alert emails stop here each day; the rest of the 95 daily cap is kept for watchlist change notices. */
export const ALERT_DAILY_CAP = 80;
/** Instant emails per user per UTC day; beyond it items wait for the digest. */
export const MAX_INSTANT_PER_USER_PER_DAY = 5;
/** Package matching never uses more D1 queries than this in one run. */
export const MAX_MATCH_QUERIES = 15;
export const MAX_WATCHED_PACKAGES = 20_000;
/** A watchlist change is mailed once it is this old, at most once an hour per user, up to this many at a time. */
export const NOTICE_MIN_AGE_MS = 10 * 60_000;
export const NOTICE_GAP_MS = HOUR_MS;
export const MAX_NOTICE_EVENTS = 100;
export const WATCH_EVENT_TTL_DAYS = 30;
/** Most distinct fixed versions listed for one package in an alert. */
export const MAX_FIXED_LISTED = 5;
