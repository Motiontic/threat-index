# red-hat fixtures

Fetched with curl 23-24 Nov 2026 (sandbox clock 23 Nov 2026). Real data.

- `changes.csv`: first 12 lines of `https://security.access.redhat.com/data/csaf/v2/vex/changes.csv`, quoted as served.
- `cve-2023-38545.json`: `https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-38545.json`, trimmed
  (587 KB to under 40 KB) by a small script: keep the first 3 ids of each `product_status` list (`fixed`,
  `known_not_affected`), then drop `product_tree` branches, relationships, `scores`, `remediations` and `threats`
  `product_ids` that no kept id uses. Notes and other fields are as served.
- Licence: Red Hat Security Data, CC BY 4.0 (`Source: Red Hat Security Data (CC BY 4.0)`).
