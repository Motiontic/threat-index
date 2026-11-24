# Sample fixtures

These JSON files are **hand-written samples**, not real MTI records. Summaries are in our own words.
CVE, ATT&CK, CWE and GHSA identifiers and their public facts (dates, CVSS scores, KEV dates) are real; every
breach, AI incident and malicious-package record is invented: its ID starts with `EXAMPLE-` and it names only
`Example Co.` / `example.com`.

`sources` on each entry lists registry ids (`@ti/sources/registry`) and may only name sources whose licence
status is `on` or `ask`.

They are read only through `app/data/fixtures.server.ts` and served by `app/data/fixture-api.server.ts`, an in-process
fake of ti-api's public routes used for tests and for local runs with `DATA_SOURCE=fixtures`.
