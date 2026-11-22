-- ti_vulns: one row per hot flaw (CVE ID, or the source ID when there is no CVE)
CREATE TABLE vulns (
  key TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, summary TEXT,
  published TEXT, modified TEXT NOT NULL,
  cvss REAL, cvss_version TEXT, cvss_source TEXT, cwe TEXT,           -- cwe: JSON array
  kev_added TEXT, kev_due TEXT, ransomware INTEGER NOT NULL DEFAULT 0,
  exploit_public INTEGER NOT NULL DEFAULT 0,
  epss REAL, epss_pct REAL, epss_date TEXT, epss_model TEXT,
  ai_related INTEGER NOT NULL DEFAULT 0, hot INTEGER NOT NULL DEFAULT 1,
  sources TEXT, doc_key TEXT                                             -- sources: JSON array
) WITHOUT ROWID;
