-- ti_signals: exploit evidence (kept as separate kinds) and the change log that powers alerts
CREATE TABLE signals (
  vuln_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('exploited_wild','public_exploit','detection','poc','ransomware')),
  source TEXT NOT NULL, ref TEXT NOT NULL, first_seen TEXT NOT NULL, evidence_date TEXT, url TEXT,
  PRIMARY KEY (vuln_key, kind, source, ref)
) WITHOUT ROWID;

CREATE TABLE changes (
  id TEXT PRIMARY KEY, entity_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('newly_exploited','public_exploit','epss_band','fix_released','cvss_change','breach_notice')),
  old TEXT, new TEXT, at TEXT NOT NULL, source TEXT
) WITHOUT ROWID;
CREATE INDEX changes_by_time ON changes (at);
