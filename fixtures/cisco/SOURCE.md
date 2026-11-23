# cisco fixtures

Fetched with curl 23-24 Nov 2026 (sandbox clock 23 Nov 2026). Cisco's edge answers `403 Access Denied` to some
User-Agents (a custom one and a browser-like one); curl's default User-Agent gets `200`.

- `changes.csv`: first 12 lines of `https://www.cisco.com/.well-known/csaf/changes.csv`, unquoted as served.
- `cisco-sa-fmc-mulivulns-4psnfwvx.json`: `https://www.cisco.com/.well-known/csaf/2026/cisco-sa-fmc-mulivulns-4psnfwvx.json`
  (5 CVEs), trimmed like the Red Hat one (first 3 ids per `product_status` list per vulnerability).
- Licence: none stated; source marked `ask`.
