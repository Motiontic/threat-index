# debian parser fixtures

Fetched 23 Nov 2026 from `https://osv-vulnerabilities.storage.googleapis.com/Debian/<id>.json`. Debian security
data, licence status `ask` (fixtures are used for tests only). `details` cut to 600 characters; reformatted JSON.

- `DEBIAN-CVE-2026-97845.json`: per-CVE record (CVE in `upstream`).
- `DSA-6654-1.json`: notice record (bundles many CVEs); the parser skips it.
