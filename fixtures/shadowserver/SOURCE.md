# shadowserver

No fixtures and no pull. Checked 24 Nov 2026 (sandbox clock 23 Nov 2026): `POST https://transform.shadowserver.org/api2/reports/list`
and `.../reports/types` answer `401 {"error":"Invalid API key or HMAC"}`; `GET /api2/` answers `404`. The API needs a key and a
per-request HMAC signature, which `CredentialName` does not cover, and no public feed was found.
Licence: no stated licence; source marked `ask`.
