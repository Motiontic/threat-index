# cvss-visibility: show CVSS scores when the MTI source that delivered them is visible

## Why

`vulns.cvss_source` holds who scored the vulnerability: a CNA or ADP name such as `CISA-ADP`, `GitHub_M`,
`Patchstack`, `VulDB` or `NVD` (`packages/core/src/types.ts`: "who gave the score"). Both `GET /v1/entries/:id`
(`apps/api/src/routes/entries.ts`, around lines 113–160) and the package check
(`apps/api/src/lib/packages-answer.ts`, around line 176) pass that name to the source-display check, which knows
only MTI source IDs (`cve-list`, `nvd`, `github-advisory-db`…). An unknown ID counts as `hidden`, so every score
is hidden.

Result on production: 183,606 vulnerabilities have a CVSS score in D1, and none is shown on entry pages or in
package checks. Log4Shell (CVE-2021-44228, CVSS 10) shows no score. The "plan" priority (CVSS 7.0 or more) then
rests only on advisory severity labels.

## What to build

1. **Visibility follows the delivering source.** Decide whether a score may be shown by the MTI source that
   delivered it, never by the scorer's name.
   - Find where the score is written: the linker merge in `packages/linker/src/draft.ts`, and the parsers that set
     `cvssSource`. Record which MTI source supplied it.
   - Prefer no schema change. If `vulns` already keeps the delivering source for the score, or it can be derived
     without ambiguity (for example the score always comes from the `cve-list` record), use that. If a column is
     needed, add `cvss_from TEXT` in a new vulns migration, filled by the linker on new writes. Treat existing rows
     with a CVSS but no `cvss_from` as delivered by the source the derivation rule names, and say in PROOF.md how
     that was decided.
   - Keep every licence rule as it is. A score delivered by a `hidden` source stays hidden.
2. **The scorer's name is attribution.** Show it as text, for example "CVSS 10.0 (scored by CISA-ADP)". Don't use it
   for visibility, and don't add it to the source-credit list unless it is an MTI source.
3. **Same rule everywhere.** Apply it to entry pages, the package check (`cvss` and the ranking), search previews
   (`apps/api/src/lib/preview.ts`) and any other reader of `cvss_source` (`grep -rn cvss_source apps packages`).
4. **MCP output.** The MCP check tool passes `cvss` through already; no MCP change is expected. Confirm it with a
   test.

## Tests

- An entry with `cvss_source = 'CISA-ADP'`, delivered by a visible source, shows its score and the attribution.
- A score delivered by a source in `hidden` display mode stays hidden.
- The package check ranks a CVSS 9.8 match as `plan` or higher when nothing else applies.
- Regression: Log4Shell-shaped fixture data shows CVSS 10.

## Not in scope

- EPSS. The EPSS source isn't wired yet and waits on a licence decision.
- Changing any source's display mode.

## Acceptance criteria

1. `pnpm build` and the Workers tests pass; the lockfile is unchanged.
2. Scores delivered by visible sources are shown everywhere a score is read, with the scorer named as attribution.
3. No score from a hidden source becomes visible.
