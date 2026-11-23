# hhs-ocr fixtures

- `listing.html`: `https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf`, fetched 23 Nov 2026 with
  `ThreatIndex-test/0.1 (+https://github.com/Motiontic/threat-index)` (HTTP 200). Real markup, trimmed to the table
  header and the first 3 rows; inline scripts removed.
- `rows.json`: the first 3 objects are the rows the page pattern yields from `listing.html` (checked by
  `page-breach-us.workers.test.ts`). The last 3 are **hand-written**: `individuals` `n/a`, a bad date `02/30/2026`, an
  unknown key.
- Licence: US government work; source marked `on`.
