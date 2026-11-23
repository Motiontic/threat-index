# nvd fixtures

- `CVE-2024-3400.json`: **real**, fetched 2026-11-23 from
  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400 (NVD, public domain; credit
  "This product uses the NVD API but is not endorsed or certified by the NVD."). Has a Secondary (CNA) and a Primary (NVD) CVSS 3.1 metric.
- `rejected.json`: **hand-written** 2026-11-23 (CVE-2023-99001, `vulnStatus: Rejected`).
- `pattern-*` and `PATTERNS.md` belong to the pattern tests.

Endpoint checks (status, date format) are in the run's proof/curl-checks.txt, 2026-11-23.
