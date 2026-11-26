-- One row per source record that names affected packages, for every year (not only the hot set).
CREATE TABLE package_advisories (
  source TEXT NOT NULL, source_id TEXT NOT NULL,
  vuln_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','withdrawn','rejected')),
  summary TEXT,                         -- plain text, at most 300 characters, as the source wrote it
  severity TEXT,                        -- CVSS base score ("9.8") or the source's label ("HIGH")
  reviewed INTEGER NOT NULL DEFAULT 0,  -- 1 when fix versions come from the ecosystem's own database or a reviewed advisory
  url TEXT, published TEXT, modified TEXT NOT NULL,
  PRIMARY KEY (source, source_id)
) WITHOUT ROWID;
CREATE INDEX package_advisories_by_vuln ON package_advisories (vuln_key);

-- One row per affected range (or exact-version list) in such a record.
CREATE TABLE affected (
  ecosystem TEXT NOT NULL,              -- canonical OSV name: npm, PyPI, Go, Maven, crates.io, ...
  name TEXT NOT NULL,                   -- normalised with @ti/core/packages normaliseName
  source TEXT NOT NULL, source_id TEXT NOT NULL,
  range_no INTEGER NOT NULL,            -- position of the range within the record, from 0
  vuln_key TEXT NOT NULL,
  range_type TEXT NOT NULL CHECK (range_type IN ('SEMVER','ECOSYSTEM','EXACT')),
  introduced TEXT NOT NULL DEFAULT '0',
  fixed TEXT, last_affected TEXT,
  versions TEXT,                        -- JSON array when range_type = 'EXACT'
  PRIMARY KEY (ecosystem, name, source, source_id, range_no)
) WITHOUT ROWID;
CREATE INDEX affected_by_record ON affected (source, source_id);
CREATE INDEX affected_by_vuln ON affected (vuln_key);
