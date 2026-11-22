-- ti_control: sources, bookmarks, runs, E2B jobs, budget meter
CREATE TABLE sources (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, pattern TEXT NOT NULL, cadence TEXT NOT NULL,
  licence TEXT NOT NULL CHECK (licence IN ('on','ask','wait','link')),
  ingest INTEGER NOT NULL DEFAULT 1, display TEXT NOT NULL DEFAULT 'full',
  credit TEXT, homepage TEXT, updated_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE cursors (
  source_id TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT, etag TEXT, updated_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE runs (
  id TEXT PRIMARY KEY, source_id TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
  status TEXT NOT NULL, found INTEGER NOT NULL DEFAULT 0, written INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0, error TEXT
) WITHOUT ROWID;
CREATE INDEX runs_by_source ON runs (source_id, started_at);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT, status TEXT NOT NULL,
  sandbox_id TEXT, created_at TEXT NOT NULL, finished_at TEXT, manifest_key TEXT, error TEXT
) WITHOUT ROWID;

CREATE TABLE budget (
  day TEXT PRIMARY KEY, d1_writes INTEGER NOT NULL DEFAULT 0, queue_ops INTEGER NOT NULL DEFAULT 0,
  r2_class_a INTEGER NOT NULL DEFAULT 0, emails_sent INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
