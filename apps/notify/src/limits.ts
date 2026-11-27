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
/** Alert emails stop here each day; the rest of the 95 daily cap belongs to watchlist change notices. */
export const ALERT_DAILY_CAP = 75;
/** Watchlist change notices have their own budget: this many a day in all, and this many per user. */
export const NOTICE_DAILY_CAP = 20;
export const NOTICE_PER_USER_PER_DAY = 2;
/** Rows one user can have queued; matching drops (and counts) the excess. */
export const MAX_QUEUED_PER_USER = 200;
/** The queue is read per user: at most this many of a user's newest rows, so one backlog can't fill the read. */
export const MAX_QUEUE_READ_PER_USER = 50;
/** Instant emails per user per UTC day; beyond it items wait for the digest. */
export const MAX_INSTANT_PER_USER_PER_DAY = 5;
/** Size of the package list one run reads watchers for (one statement). Changes past it wait for the next run. */
export const MAX_PAIR_BYTES = 400_000;
/** A watchlist change is mailed once it is this old, at most once an hour per user, up to this many at a time. */
export const NOTICE_MIN_AGE_MS = 10 * 60_000;
export const NOTICE_GAP_MS = HOUR_MS;
export const MAX_NOTICE_EVENTS = 100;
/** Instant-count rows are kept this many days. */
export const INSTANT_COUNT_TTL_DAYS = 2;
export const WATCH_EVENT_TTL_DAYS = 30;
/** Most distinct fixed versions listed for one package in an alert. */
export const MAX_FIXED_LISTED = 5;
