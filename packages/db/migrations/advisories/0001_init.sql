-- ti_advisories: every source record; doubles as the alias map (any ID -> vuln_key)
CREATE TABLE advisories (
  source TEXT NOT NULL, source_id TEXT NOT NULL, vuln_key TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','withdrawn','rejected')),
  published TEXT, modified TEXT NOT NULL, url TEXT, licence TEXT,
  PRIMARY KEY (source, source_id)
) WITHOUT ROWID;
CREATE INDEX advisories_by_vuln ON advisories (vuln_key);
