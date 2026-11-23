# bsi-cert-bund fixtures

- URLs: `https://wid.cert-bund.de/.well-known/csaf/white/changes.csv` (range read) and
  `.../white/2026/wid-sec-w-2026-4715.json`. Fetched 23 Nov 2026. Licence: `ask`.
- `changes-head.csv`: the first 5 lines of the real file.
- `wid-sec-w-2026-4715.json`: the real document. `product_tree` replaced by a one-branch stub, each vulnerability's
  `product_status` replaced by a stub, long `notes` texts cut. IDs, dates and CVEs are real.
- `amber.json`, `no-cve.json`: **hand-written** copies of it: `amber.json` with TLP `AMBER` and id `WID-SEC-W-2026-0001`;
  `no-cve.json` with `vulnerabilities: []` and id `WID-SEC-W-2026-0002`.
