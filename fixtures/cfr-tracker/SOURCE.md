# cfr-tracker fixtures

- `incidents.csv`: `https://static.cfr.org/cyber-operations/data/cyber-operations-incidents.csv`, fetched 23 Nov 2026.
  Real data, trimmed to the header and 7 rows: the two "Roshan" rows (same title and date, different
  `Affiliations`), one with an empty `Date`, "Nodaria" and "Sandworm" and "APT 36" (`Also known as …`), and
  "Antlion" (empty `Sponsor` and `Affiliations`). Rewritten through a CSV writer.
- Licence: no licence checked here; source marked `ask`.
