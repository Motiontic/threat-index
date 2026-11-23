-- notify engine: why a change was queued, the collection cursor, and one row per email attempt.
-- email_sends holds no user ID or address (idem_key is a hash), so account deletion needs no change.
ALTER TABLE alert_queue ADD COLUMN via TEXT NOT NULL DEFAULT 'watch'; -- 'watch' | 'search:<saved search id>'
CREATE TABLE notify_state (name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE email_sends (
  idem_key TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('instant','daily','weekly')),
  change_count INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','sent','dry_run','failed')),
  provider_id TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
) WITHOUT ROWID;
