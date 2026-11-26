-- Rebuilds `changes` so its CHECK list also allows new_advisory (SQLite can't alter a CHECK).
CREATE TABLE changes_new (
  id TEXT PRIMARY KEY, entity_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('newly_exploited','public_exploit','epss_band','fix_released','cvss_change','breach_notice','new_advisory')),
  old TEXT, new TEXT, at TEXT NOT NULL, source TEXT
) WITHOUT ROWID;
INSERT INTO changes_new (id, entity_key, kind, old, new, at, source)
  SELECT id, entity_key, kind, old, new, at, source FROM changes;
DROP TABLE changes;
ALTER TABLE changes_new RENAME TO changes;
CREATE INDEX changes_by_time ON changes (at);
