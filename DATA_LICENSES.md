# Data sources and licences

**This repository contains no third-party data.** The software fetches data at run time from public sources. Each source keeps its own licence and terms, and the registry (`packages/sources/src/registry.ts`) records how the code treats each one.

| Status | Meaning in the code                                                                          | Count |
| ------ | -------------------------------------------------------------------------------------------- | ----- |
| `on`   | The licence allows commercial use with attribution. Ingested and shown, with the credit line | 24    |
| `ask`  | No written terms found. Ingested and shown with credit; written confirmation is being sought | 23    |
| `wait` | Terms need written permission or forbid commercial use. **Off by default**                   | 6     |
| `link` | All rights reserved. Only ID, title, date and link are kept, until permission                | 2     |

**`wait` (off by default):** VulnCheck, CERT-FR, Malpedia, AI Incident Database, ransomware.live, EuRepoC.
**`link` (link-only):** Zero Day Initiative, DataBreaches.net.

Notes:

- **NVD:** every page that uses NVD data shows "This product uses the NVD API but is not endorsed or certified by the NVD."
- **OSV.dev:** licences differ by source. Chainguard and Wolfi records (CC BY-NC-ND) are excluded. Ubuntu and Alpine records (CC BY-SA) are labelled share-alike.
- **AI Incident Database:** even after permission, report article text is never stored.
- **Exploit sources** (Exploit-DB, Metasploit, PoC collectors): metadata only (ID, date, URL, CVE). Exploit code is never fetched.

**If you run your own copy,** you are responsible for following each source's current terms. Statuses here reflect our review on 22 November 2026 and are not legal advice.
