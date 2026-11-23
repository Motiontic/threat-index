# mitre-atlas fixtures

- URL: https://github.com/mitre-atlas/atlas-data/releases/latest/download/stix-atlas.json (release v2026.10)
- Fetched: 2026-11-23
- `stix-sample.json`: real objects cut from the asset with a script: the `x-mitre-collection` (`x_mitre_contents` cut to 3 entries if present),
  `attack-pattern`s `AML.T0000`, `AML.T0000.000`, `AML.T0051`, `AML.T0051.000`, and the first `x-mitre-tactic`, `subtechnique-of`
  `relationship` and `course-of-action`.
  **Hand-written:** the last object, type `x-example-new`, added to test `unknownFields`.
- `pattern-manifest.yaml`: the real first 256 bytes of https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml
  (cut mid-line on purpose); line 1 is `- release: '2026.10'`.
- Licence: Apache-2.0 (ATLAS data); credit "Source: MITRE ATLAS™".
