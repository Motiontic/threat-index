import { src } from '../define';

const URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';

export default src('mitre-attack', 'MITRE ATT&CK', 'Attacker techniques', 'heavy', 'weekly', 'on', {
  heavy: true,
  credit: 'Source: MITRE ATT&CK®',
  parser: 'stix',
  pull: {
    heavy: {
      url: URL,
      // The collection object at the top of the file carries the version.
      version: { url: URL, pattern: '"x_mitre_version":\\s*"([\\d.]+)"', bytes: 2048 },
    },
    jobKind: 'first-load',
  },
});
