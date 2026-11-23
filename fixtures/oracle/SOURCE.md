# oracle fixtures

- `cpujan2025csaf.json`: `https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json` (301 to
  `/a/tech/docs/...`), fetched 23-24 Nov 2026. The 1.4 MB January 2025 Critical Patch Update, cut to its first 3
  vulnerabilities (of 267) and the first 3 products of each `product_status` list, tree entries no kept id uses dropped.
- Copyright line in `document.distribution.text`: "Copyright © Oracle. All rights reserved."
- The source is **not wired**: `/.well-known/csaf/provider-metadata.json` is 404, there is no index or
  `changes.csv`, and the one quarterly file has a new URL each quarter and passes the 5 MB Worker limit. See
  `packages/sources/src/sources/oracle.ts`. The parser handles these documents, so wiring later is config only.
- Licence: source marked `ask`.
