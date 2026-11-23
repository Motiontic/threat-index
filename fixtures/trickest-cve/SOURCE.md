# trickest-cve fixture

- URL: https://raw.githubusercontent.com/trickest/cve/main/2024/CVE-2024-3400.md
- Fetched: 2026-11-23 (the real file was fetched with curl, HTTP 200)
- Licence: MIT (GitHub API `license.spdx_id` = MIT for `trickest/cve`; the raw `LICENSE` file is the MIT text, "Copyright (c) 2022 Trickest"). Default branch: `main`.
- `CVE-2024-3400.md`: the real file with the `#### Github` list cut to its first 5 links. The heading, description and Reference sections are unchanged.
- Hand-written: `edge-cases.md` (a repeated link, a trailing slash, a deep path, a non-GitHub link under the GitHub heading, a link under an unknown `### Extra` heading, a Reference section with only non-GitHub links) and `reference-only.md` (a GitHub link only under `#### Reference`). Their names and CVE ids are invented.
