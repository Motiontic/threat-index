# jvn fixtures

- URL: `https://jvndb.jvn.jp/en/rss/jvndb.rdf` ("Update Entry"). Fetched 23 Nov 2026. Licence: `ask`.
- `jvndb.rdf`: the real channel header (the `rdf:Seq` cut to 3 entries) and three items: JVNDB-2026-000175 (real,
  one CVE), JVNDB-2026-042618 (real, two CVEs) and JVNDB-2026-099999 (**hand-edited** from a real item: the CVE
  references and CVE text removed, the id changed, and an unknown `<sec:foo>` element added).
- `bad-id.rdf`: **hand-written** from item 1 with the identifier changed to `JVN#1`, to test the id check.
