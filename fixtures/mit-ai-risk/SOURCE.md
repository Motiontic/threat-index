# mit-ai-risk: no pull

Checked 24 Nov 2026 (spec). No parser, no pull, no fixture.

- The data is a Google Sheet whose ID changes with each release (V4 of 3 Dec 2025 is
  `15LeHcpeuZC9txkvcaMoh3sUhkMvdMMry69xxXL46DT0`, tab `gid=1710822211`, header on row 3, about 1.6 MB, CC BY 4.0), so
  no URL stays stable.
- Its rows are risk statements taken from papers (`Ev_ID` like `01.01.00`), not incidents, and
  `TechniqueRecord.framework` has no value for them.
- The MIT AI Incident Tracker is an Airtable embed with no export.
