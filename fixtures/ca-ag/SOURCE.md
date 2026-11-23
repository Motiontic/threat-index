# ca-ag fixtures

- `list.html`: `https://oag.ca.gov/privacy/databreach/list`, fetched 23 Nov 2026 with
  `ThreatIndex-test/0.1 (+https://github.com/Motiontic/threat-index)` (HTTP 200). Real markup, trimmed to the table head
  and 5 rows: the 3 newest, plus the real Mercadien row (`n/a` dates) and the real Acadia row (two dates). Nothing was
  hand-written in the HTML.
- `rows.json`: the first 5 objects are the rows the page pattern yields from `list.html` (checked by
  `page-breach-us.workers.test.ts`). The 6th is **hand-written**: its link is on another host.
- Licence: no stated licence; source marked `ask`.
