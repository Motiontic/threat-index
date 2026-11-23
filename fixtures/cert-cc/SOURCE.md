# cert-cc fixtures

- URL: `https://kb.cert.org/vuls/atomfeed/` and `https://kb.cert.org/vuls/api/604762/`. Fetched 23 Nov 2026 (feed
  `Last-Modified` 20 Nov 2026). Licence: `ask`.
- `atomfeed.xml`: the real feed header and three real entries (VU#604762, VU#644655, VU#124705), trimmed. The
  `summary` and `content` prose is replaced by one invented sentence; the "CVE IDs" block keeps the real shape
  (`<a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId=YYYY-NNNN">`). VU#604762 has four CVEs in that block
  and `CVE-2026-49999` **invented** in the prose only. VU#644655 has one CVE, VU#124705 has none.
- `note-604762.json`: the real note API response with long prose fields cut to about 160 characters.
