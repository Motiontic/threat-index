import { src } from '../define';

export default src('cwe', 'CWE', 'Weakness types', 'heavy', 'weekly', 'on', {
  heavy: true,
  credit: 'Source: CWE™ (MITRE)',
  parser: 'cwe',
  pull: {
    heavy: {
      url: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
      version: { url: 'https://cwe.mitre.org/data/downloads.html', pattern: 'CWE List Version ([\\d.]+)' },
    },
  },
});
