import { src } from '../define';

export default src('mitre-atlas', 'MITRE ATLAS', 'AI attack techniques', 'heavy', 'weekly', 'on', {
  heavy: true,
  credit: 'Source: MITRE ATLAS™',
  parser: 'stix',
  pull: {
    heavy: {
      url: 'https://github.com/mitre-atlas/atlas-data/releases/latest/download/stix-atlas.json',
      // The manifest can name a release a few minutes before its asset exists; the next weekly run catches up.
      version: {
        url: 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml',
        pattern: "release: '([\\d.]+)'",
        bytes: 256,
      },
    },
    jobKind: 'first-load',
  },
});
