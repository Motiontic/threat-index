# capec fixtures

- `capec-sample.xml`: **hand-written** 2026-11-23, trimmed to the shape of https://capec.mitre.org/data/xml/capec_latest.xml
  (CAPEC 3.9): CAPEC-66 (child of 248), CAPEC-248, one deprecated entry. CAPEC is (c) MITRE, free to use with credit.
- Endpoint checked 2026-11-23: a 2048-byte range request returns 206 and the root has `Version="3.9"`, matched by `Version="([\d.]+)"`.
