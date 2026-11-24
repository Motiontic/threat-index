# cisa-kev fixture

- Source: CISA Known Exploited Vulnerabilities catalogue, JSON feed
  (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Licence: CC0.
- Trimmed to one entry. The catalogue version, date added and due date are as published; the description was shortened for tests.

## real-feed.json

A trimmed copy of the live feed fetched on 24 Nov 2026 (catalogVersion 2026.11.23, 1,792 entries): the first
entry, the first with `knownRansomwareCampaignUse: "Known"`, and the last. Includes the `forensicTriage` field the
parser does not know yet. CC0.
