import { src } from '../define';

export default src('capec', 'CAPEC', 'Attack patterns', 'heavy', 'weekly', 'on', {
  heavy: true,
  credit: 'Source: CAPEC™ (MITRE)',
  parser: 'cwe',
  pull: {
    heavy: {
      url: 'https://capec.mitre.org/data/xml/capec_latest.xml',
      // The root element, near the top of the file, carries the version.
      version: {
        url: 'https://capec.mitre.org/data/xml/capec_latest.xml',
        pattern: 'Version="([\\d.]+)"',
        bytes: 2048,
      },
    },
  },
});
