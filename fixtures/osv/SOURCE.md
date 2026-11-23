# osv parser fixtures

- `GO-2026-5006.json`: `https://osv-vulnerabilities.storage.googleapis.com/Go/GO-2026-5006.json`, fetched 24 Nov 2026
  (sandbox clock 23 Nov 2026). Untrimmed. Go vulnerability database record, CC-BY 4.0.
- `MAL-2026-12900.json`: `https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2026-12900.json`, same fetch date.
  OpenSSF malicious-packages, CC-BY 4.0. `details` cut to 600 characters.
- `no-cve.json`, `withdrawn.json`, `bad.json`: hand-written, invented text (`RUSTSEC-` id, no aliases, two
  introduced/fixed pairs, a `last_affected` range, a `GIT` range, one unknown top-level key; a withdrawn record; a
  record with no `id`).
- `pattern-*`, `PATTERNS.md`: for the changelist pattern tests (see `PATTERNS.md`).
