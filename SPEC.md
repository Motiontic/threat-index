# source-gaps: every enabled source runs on a new environment, starting with CISA KEV

## Why

Production (deployed 24 Nov 2026) and staging both show empty or thin sections. The 06:00 UTC collector run
on production recorded (`ti_control.runs`):

- `cisa-kev` skipped: `source has no pull config yet`. `packages/sources/src/sources/cisa-kev.ts` sets a parser
  but no `pull`, so the main "exploited in the wild" source never runs on its own. Staging only has KEV rows
  because they were loaded by hand.
- `nvd` failed: `continuation not queued`. In `apps/collector/src/step.ts` the step-limit error
  (`MAX_STEPS_PER_RUN`) is thrown inside the `try` around `env.JOBS.send` and reported as a failed run. A long
  first run of a `since` source must stop at the limit, keep its cursor, and continue on the next tick.
- `sec-edgar` failed: `PatternError: unexpected response (403)`. SEC requires a User-Agent that names the
  sender and gives a contact email (for example `Motiontic Threat Index ops@motiontic.com`). The collector's
  `USER_AGENT` is `ThreatIndex/0.1 (+https://github.com/...; ops@motiontic.com)`.
- `zdi`, `databreaches-net` (ingest `link`) and `cisa-vulnrichment` (read inside CVE List records) are
  reported as `skipped … no pull config yet`, which reads like a fault.
- Sources with a `daily`, `weekly`, `monthly` or `quarterly` cadence never ran on production: MITRE ATT&CK,
  MITRE ATLAS, CAPEC, CWE, HHS OCR, AIAAIC, UK ICO, MIT AI Risk and others. They wait for their cadence's
  cron (weekly ones run Mondays 05:00), so a new environment shows no techniques, no AI incidents and few
  breaches for up to a week. Staging has 0 techniques and 0 incidents for the same reason.

## What to build

1. **CISA KEV pull.** Give `cisa-kev` a `fingerprint` pull of the official JSON feed
   (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`), parsed by the
   existing `kev` parser. Check the parser's input shape against a saved fixture of the real feed (fetch it
   once in the sandbox and save a trimmed copy as a fixture).
2. **Step limit is not a failure.** When a run reaches `MAX_STEPS_PER_RUN`, it ends `ok` (or a distinct
   `partial` status if the schema allows it without a migration; otherwise `ok` with the count) and keeps its
   cursor, so the next tick continues from it. Only a real `JOBS.send` failure reports `continuation not
   queued`. Add a test.
3. **SEC User-Agent.** Requests to `*.sec.gov` send `Motiontic Threat Index <contact>` where `<contact>` is
   the configured contact email from `USER_AGENT`'s contact part (or a new optional `CONTACT_EMAIL` var fed by
   `TI_CONTACT_EMAIL` in `apps/collector/wrangler.jsonc`, both top level and `env.staging`). Without a contact,
   skip SEC with a clear `skipped` reason instead of a 403. Test the header.
4. **Honest skip reasons.** `link` sources are recorded as skipped with reason `link only: not ingested`;
   `cisa-vulnrichment` as `read from CVE List records`. Sources whose ingest is `wait` keep their current
   behaviour (never fetched).
5. **First run regardless of cadence.** On each 3-hourly tick, a source whose ingest allows fetching and that
   has never had an `ok` run is due now, whatever its cadence. Keep the per-tick budget: start at most a small
   fixed number of never-run heavy sources per tick (heavy sources go to E2B jobs, and the API allows at most
   `MAX_ACTIVE_JOBS` active jobs), so a new environment fills within a day without exceeding the job limit.
   After that first `ok` run, the normal cadence applies. Test with a fake clock and a fresh database.
6. **Ops view.** The `/ops` data (API `admin-ops`) lists each source's last run status and reason, if it does
   not already, so the next gap is visible without SQL. Keep it small.

## Not in scope

The web pages (another loop owns `apps/web`), turning on any `wait` source, migrations unless unavoidable,
new dependencies, `pnpm-lock.yaml`.

## Files this loop owns

`packages/sources/src/` (source definitions and the parsers they use, with fixtures and tests),
`apps/collector/` (src, test, wrangler.jsonc), `apps/api/src/routes/admin-ops.ts` and its test,
`.github/workflows/deploy.yml` only to add `TI_CONTACT_EMAIL` if a new var is added, `docs/adding-a-source.md`.

## Acceptance criteria

1. `pnpm build` and `pnpm test:workers` pass.
2. Tests cover: KEV pull and parse from the fixture; step limit keeps the cursor and does not fail; SEC header
   and the no-contact skip; first-run-regardless-of-cadence with the per-tick cap; the new skip reasons.
3. The proof lists, for every source in `packages/sources/src/sources/`, whether a fresh environment will now
   fetch it on the first tick, a later tick, or never (and why).
