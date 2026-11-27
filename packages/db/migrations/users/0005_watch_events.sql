-- MCP watchlist change log (for the "your watchlist was changed" email) and a wider email_sends.kind.
-- Only changes made through MCP are recorded. Rows older than 30 days are deleted by notify.
CREATE TABLE watch_events (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, at TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('add','remove','alerts_on','digest_on')),
  target TEXT NOT NULL,                 -- 'pkg:<ecosystem>/<name>' or 'entry:<key>' or 'settings'
  via TEXT NOT NULL CHECK (via IN ('mcp')),
  client_host TEXT,                     -- host of the OAuth client_id URL, or NULL
  notified_at TEXT                      -- set when the change notice email went out
);
CREATE INDEX watch_events_by_user ON watch_events (user_id, at);
CREATE INDEX watch_events_pending ON watch_events (notified_at, user_id);

-- Instant emails sent per user per UTC day, for the daily cap per user. Rows older than 2 days are deleted by notify.
CREATE TABLE instant_counts (
  user_id TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
) WITHOUT ROWID;

-- SQLite can't alter a CHECK: rebuild email_sends with 'watch_notice' allowed.
CREATE TABLE email_sends_new (
  idem_key TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('instant','daily','weekly','watch_notice')),
  change_count INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','sent','dry_run','failed')),
  provider_id TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
) WITHOUT ROWID;
INSERT INTO email_sends_new (idem_key, kind, change_count, status, provider_id, error, created_at, updated_at)
  SELECT idem_key, kind, change_count, status, provider_id, error, created_at, updated_at FROM email_sends;
DROP TABLE email_sends;
ALTER TABLE email_sends_new RENAME TO email_sends;
