# enisa fixtures

- `exploited-search.json`: `https://euvdservices.enisa.europa.eu/api/search?exploited=true&page=0&size=100`, fetched
  24 Nov 2026 (sandbox clock 23 Nov 2026). Real; `items` cut from 100 to 3, `total` left as served (1809).
- `entry.json`: `https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-31989`, same fetch date. Real, untrimmed.
- `no-cve.json`: hand-written, invented text. Only a GHSA alias, a 4.0 score, `exploitedSince`, and one unknown
  field (`vendorNotes`).
- Licence: no stated licence; source marked `ask`.
