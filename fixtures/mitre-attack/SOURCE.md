# mitre-attack fixtures

- URL: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json (ATT&CK enterprise, v20.1)
- Fetched: 2026-11-23
- `enterprise-sample.json`: real objects cut from the file with a script: the `x-mitre-collection` with `x_mitre_contents` cut to 3 entries;
  `attack-pattern`s `T1190`, `T1566`, `T1566.001`, `T1566.002`; one revoked (`T1066`) and one deprecated (`T1153`) `attack-pattern`; and the first
  `x-mitre-tactic`, `relationship`, `malware` and `x-mitre-analytic`. Descriptions are the real ones. Nothing is hand-written.
- `pattern-version.json`: the real first 2,048 bytes of the file (cut mid-object on purpose); `"x_mitre_version": "20.1"` is on line 10.
- Licence: MITRE ATT&CK terms of use; credit "Source: MITRE ATT&CK®".
