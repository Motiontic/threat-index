# ubuntu parser fixtures

Fetched 23 Nov 2026 from `https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/<id>.json`. Ubuntu security
data, licence status `ask` (fixtures are used for tests only). `details` cut to 600 characters; reformatted JSON.

- `UBUNTU-CVE-2026-99315.json`: per-CVE kernel record, `affected` trimmed from 268 entries to the first 3.
- `USN-9176-1.json`: notice record; the parser skips it.
