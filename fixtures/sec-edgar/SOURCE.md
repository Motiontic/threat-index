# sec-edgar fixtures

- `current-8k.atom`: shape of `https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=8-K&company=&dateb=&owner=include&start=0&count=100&output=atom`.
  **All five entries are hand-written**: from the loop sandbox, SEC answered 403 (AkamaiGHost) to
  `ThreatIndex-test/0.1 (+https://github.com/Motiontic/threat-index)` on 23 Nov 2026 (see proof/curl-status.txt), so
  the real feed could not be fetched. They copy the shape in SPEC.md. BridgeBio, Northwind and Contoso are non-1.05
  entries (BridgeBio's title and ids are from the spec's real example; its items are Item 8.01/9.01). Park Dental
  Partners (CIK 0002069604, accession 0001104659-26-115541, filed 2026-10-13) uses the facts in SPEC.md. The `8-K/A`
  (Example Health Holdings) is invented and has a link CIK (7654321) that differs from the title CIK (0001234567).
- Licence: SEC filings are public domain; source marked `on`.
