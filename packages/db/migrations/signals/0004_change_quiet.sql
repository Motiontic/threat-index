-- A change row may alert only when `quiet` is null. `event_at` is when the event happened at the source.
ALTER TABLE changes ADD COLUMN event_at TEXT;
ALTER TABLE changes ADD COLUMN quiet TEXT CHECK (quiet IN ('old','first_load','held'));
CREATE INDEX changes_alerts ON changes (at, id) WHERE quiet IS NULL;
