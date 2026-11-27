-- Alertable change rows a run has written so far (the per-run hold counts against this).
ALTER TABLE runs ADD COLUMN alerts INTEGER NOT NULL DEFAULT 0;
