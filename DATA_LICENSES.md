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

## Every source

One row per source file in `packages/sources/src/sources/`, in id order. The registry is the source of truth; when you add or change a source, update its row here.

| Id | Name | Pattern | Cadence | Status |
| -- | ---- | ------- | ------- | ------ |
| `aiaaic` | AIAAIC | `fingerprint` | `weekly` | `ask` |
| `aiid` | AI Incident Database | `heavy` | `weekly` | `wait` |
| `avid` | AVID | `git` | `weekly` | `on` |
| `bsi-cert-bund` | BSI CERT-Bund | `changelist` | `3h` | `ask` |
| `ca-ag` | California AG | `page` | `daily` | `ask` |
| `capec` | CAPEC | `heavy` | `weekly` | `on` |
| `cert-cc` | CERT/CC | `feed` | `daily` | `ask` |
| `cert-fr` | CERT-FR | `feed` | `daily` | `wait` |
| `cert-in` | CERT-In | `page` | `daily` | `ask` |
| `cfr-tracker` | CFR Cyber Operations Tracker | `fingerprint` | `weekly` | `ask` |
| `cisa-advisories` | CISA advisories | `feed` | `3h` | `on` |
| `cisa-kev` | CISA KEV | `fingerprint` | `3h` | `on` |
| `cisa-vulnrichment` | CISA Vulnrichment | `git` | `with-cve-list` | `on` |
| `cisco` | Cisco | `changelist` | `3h` | `ask` |
| `cpe-dictionary` | CPE dictionary | `since` | `daily` | `on` |
| `csis` | CSIS significant incidents | `heavy` | `monthly` | `ask` |
| `cve-list` | CVE List | `git` | `3h` | `on` |
| `cwe` | CWE | `heavy` | `weekly` | `on` |
| `databreaches-net` | DataBreaches.net | `feed` | `3h` | `link` |
| `debian` | Debian | `changelist` | `3h` | `ask` |
| `enisa` | ENISA (EUVD + EU KEV) | `fingerprint` | `3h` | `ask` |
| `epss` | EPSS | `since` | `daily` | `ask` |
| `eurepoc` | EuRepoC | `heavy` | `monthly` | `wait` |
| `exploit-db` | Exploit-DB | `heavy` | `3h` | `ask` |
| `gcve` | GCVE | `fingerprint` | `daily` | `ask` |
| `github-advisory-db` | GitHub Advisory DB | `git` | `3h` | `on` |
| `hhs-ocr` | HHS OCR | `page` | `daily` | `on` |
| `hibp` | Have I Been Pwned | `fingerprint` | `3h` | `on` |
| `jvn` | JVN | `heavy` | `daily` | `ask` |
| `malpedia` | Malpedia | `fingerprint` | `daily` | `wait` |
| `metasploit` | Metasploit | `heavy` | `3h` | `on` |
| `mit-ai-risk` | MIT AI Risk Repository | `heavy` | `monthly` | `on` |
| `mitre-atlas` | MITRE ATLAS | `heavy` | `weekly` | `on` |
| `mitre-attack` | MITRE ATT&CK | `heavy` | `weekly` | `on` |
| `msrc` | Microsoft MSRC | `changelist` | `daily` | `ask` |
| `nuclei-templates` | Nuclei templates | `git` | `3h` | `on` |
| `nvd` | NVD | `since` | `3h` | `on` |
| `openssf-malicious-packages` | OpenSSF malicious packages | `git` | `3h` | `on` |
| `oracle` | Oracle | `changelist` | `daily` | `ask` |
| `osv` | OSV.dev | `changelist` | `3h` | `on` |
| `poc-in-github` | PoC-in-GitHub | `git` | `3h` | `on` |
| `project-zero` | Project Zero 0-day sheet | `fingerprint` | `weekly` | `ask` |
| `ransomware-live` | ransomware.live | `since` | `3h` | `wait` |
| `red-hat` | Red Hat | `changelist` | `3h` | `on` |
| `sec-edgar` | SEC EDGAR | `feed` | `3h` | `on` |
| `shadowserver` | Shadowserver | `since` | `daily` | `ask` |
| `state-ags` | Other state AG portals | `page` | `daily` | `ask` |
| `trickest-cve` | trickest/cve | `git` | `daily` | `on` |
| `ubuntu` | Ubuntu | `changelist` | `3h` | `ask` |
| `uk-ico` | UK ICO | `heavy` | `quarterly` | `on` |
| `umd-cissm` | UMD CISSM | `heavy` | `monthly` | `ask` |
| `vcdb` | VCDB (VERIS) | `git` | `daily` | `ask` |
| `vulncheck` | VulnCheck | `since` | `3h` | `wait` |
| `wa-ag` | Washington AG | `fingerprint` | `daily` | `ask` |
| `zdi` | Zero Day Initiative | `feed` | `3h` | `link` |

**If you run your own copy,** you are responsible for following each source's current terms. Statuses here reflect our review on 22 November 2026 and are not legal advice.
