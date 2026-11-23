# cwe fixtures

- `cwec-sample.xml`: **hand-written** 2026-11-23, trimmed to the shape of https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  (CWE 5.0): CWE-74, CWE-79 (child of 74), CWE-89, one deprecated entry, one category. CWE is (c) MITRE, free to use with credit.
- Endpoints checked 2026-11-23: the zip (200, 2.1 MB) and https://cwe.mitre.org/data/downloads.html, whose
  `<h2>CWE List Version 5.0</h2>` matches the pull pattern `CWE List Version ([\d.]+)` and the zip's own Version="5.0".
- `pattern-*` and `PATTERNS.md` belong to the pattern tests.
