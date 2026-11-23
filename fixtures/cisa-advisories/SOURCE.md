# cisa-advisories fixtures

`pattern-all.xml` and `PATTERNS.md` are for the feed pattern tests. The two files below are for the parser tests.

- `all.xml`, `aa-advisory.xml`: **hand-written**, same shape as `https://www.cisa.gov/cybersecurity-advisories/all.xml`
  (RSS 2.0, `guid` `/node/<n>` with `isPermaLink="false"`, two-digit-year `pubDate`, escaped HTML `description`). The
  build sandbox got HTTP 403 from www.cisa.gov on 23 Nov 2026, so no real feed was fetched. All IDs, CVE numbers and
  texts are invented. `all.xml` has 5 items: an ICS advisory with 1 CVE, one with 6 CVEs, an alert with 1 CVE, a KEV
  announcement and a `/resources-tools/` item. `aa-advisory.xml` has one `aa26-310a` item with 120 CVEs.
- Licence: CISA publishes advisories as US government works.
