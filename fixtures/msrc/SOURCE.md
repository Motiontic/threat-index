# msrc fixtures

Fetched with curl 23-24 Nov 2026 (sandbox clock 23 Nov 2026).

- `changes.csv`: first 12 lines of `https://msrc.microsoft.com/csaf/advisories/changes.csv`, quoted as served.
- `msrc_cve-2024-38193.json`, `msrc_cve-2026-70197.json`: `https://msrc.microsoft.com/csaf/advisories/<ref>`,
  real, trimmed the same way as the Red Hat one (first 3 ids per `product_status` list; tree entries,
  relationships, `scores`, `remediations` and `threats` ids no kept id uses are dropped). 38193 has `Exploited:Yes`,
  70197 has `Exploited:No`.
- `draft.json`, `no-cve.json`: **hand-written** (not fetched). `draft.json` has `tracking.status: "draft"`;
  `no-cve.json` has one vulnerability without `cve` and an unknown document field `x_unexpected`.
- Licence: none stated; source marked `ask`.
