# vcdb fixtures

- `full-date.json` (`0565817A-…`, day, month and year) and `year-month.json` (`03EB3C45-…`, month and year only): real
  files from `data/json/submitted/` in `vz-risk/VCDB` (branch `master`), fetched from raw.githubusercontent.com on
  23 Nov 2026 (sandbox clock). Not trimmed.
- `suspected.json`, `no-victim.json`, `bad-id.json`: hand-written variants of `year-month.json` (`security_incident:
  'Suspected'`; `victim_id: 'Unknown'`, no `reference`, `plus.github: '23768'`; `incident_id: 'not-a-uuid'`).
- Licence: CC BY-SA 4.0 (`LICENSE.txt` in the repo).
