-- Account settings: instant alerts and a digest cadence at once, a user-set display name, and
-- richer saved searches. `alert_frequency` is superseded by `alert_instant` + `digest` and is no
-- longer read or written; dropping it is left for later.
ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN alert_instant INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN digest TEXT NOT NULL DEFAULT 'daily' CHECK (digest IN ('daily','weekly','off'));
UPDATE users SET alert_instant = 1, digest = 'off' WHERE alert_frequency = 'instant';
UPDATE users SET digest = alert_frequency WHERE alert_frequency IN ('weekly','off');
ALTER TABLE saved_searches ADD COLUMN params TEXT NOT NULL DEFAULT '{}';
ALTER TABLE saved_searches ADD COLUMN alerts_on INTEGER NOT NULL DEFAULT 0;
