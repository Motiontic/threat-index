-- ti_world: techniques and weaknesses, companies, breaches, incidents
CREATE TABLE techniques (
  id TEXT PRIMARY KEY, framework TEXT NOT NULL, name TEXT NOT NULL, parent TEXT, summary TEXT
) WITHOUT ROWID;

CREATE TABLE vuln_techniques (
  vuln_key TEXT NOT NULL, technique_id TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'source',
  PRIMARY KEY (vuln_key, technique_id)
) WITHOUT ROWID;

CREATE TABLE companies (
  key TEXT PRIMARY KEY, name TEXT NOT NULL, cik TEXT, domain TEXT, ticker TEXT, sector TEXT, aliases TEXT
) WITHOUT ROWID;

-- Counts are stored with their unit and never added across notices.
CREATE TABLE breach_notices (
  source TEXT NOT NULL, notice_id TEXT NOT NULL, company_key TEXT, raw_name TEXT NOT NULL,
  occurred_from TEXT, occurred_to TEXT, discovered TEXT, notified TEXT,
  count INTEGER, count_unit TEXT NOT NULL, jurisdiction TEXT, data_types TEXT, url TEXT, event_key TEXT,
  modified TEXT NOT NULL,
  PRIMARY KEY (source, notice_id)
) WITHOUT ROWID;
CREATE INDEX notices_by_company ON breach_notices (company_key);

CREATE TABLE breach_events (
  key TEXT PRIMARY KEY, company_key TEXT, first_seen TEXT NOT NULL, dates TEXT,
  counts_by_unit TEXT, notice_count INTEGER NOT NULL DEFAULT 1, confidence REAL, modified TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE incidents (
  source TEXT NOT NULL, incident_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('ai','cyber_op','cyber_event')),
  title TEXT NOT NULL, date TEXT, entities TEXT, techniques TEXT, url TEXT,
  gated INTEGER NOT NULL DEFAULT 0, modified TEXT NOT NULL,
  PRIMARY KEY (source, incident_id)
) WITHOUT ROWID;
