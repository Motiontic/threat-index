-- ti_users: single-user accounts (Clerk user ID is the key; no organisations)
CREATE TABLE users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT, created_at TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  alert_frequency TEXT NOT NULL DEFAULT 'daily' CHECK (alert_frequency IN ('instant','daily','weekly','off')),
  alert_triggers TEXT NOT NULL DEFAULT '["newly_exploited","public_exploit","epss_band","fix_released","breach_notice"]',
  digest_weekday INTEGER NOT NULL DEFAULT 1,
  email_suppressed INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT
) WITHOUT ROWID;

CREATE TABLE watch (
  user_id TEXT NOT NULL, entry_key TEXT NOT NULL, created_at TEXT NOT NULL,
  alerts_on INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id, entry_key)
) WITHOUT ROWID;
CREATE INDEX watch_by_entry ON watch (entry_key);

CREATE TABLE saved_searches (
  user_id TEXT NOT NULL, id TEXT NOT NULL, label TEXT NOT NULL, query TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, id)
) WITHOUT ROWID;

CREATE TABLE alert_queue (
  user_id TEXT NOT NULL, change_id TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, change_id)
) WITHOUT ROWID;

CREATE TABLE alerts_sent (
  user_id TEXT NOT NULL, change_id TEXT NOT NULL, sent_at TEXT NOT NULL,
  PRIMARY KEY (user_id, change_id)
) WITHOUT ROWID;

CREATE TABLE email_log (day TEXT PRIMARY KEY, sent INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;

-- Webhook idempotency (svix-id from Clerk and Resend)
CREATE TABLE webhook_events (id TEXT PRIMARY KEY, source TEXT NOT NULL, received_at TEXT NOT NULL) WITHOUT ROWID;
