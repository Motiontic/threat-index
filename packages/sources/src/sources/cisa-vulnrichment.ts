import { src } from '../define';

// No `pull` on purpose. CISA's data reaches us inside cvelistV5 records (the `CISA-ADP` container),
// parsed by `cve-json5` and attributed to this source. Pulling `cisagov/vulnrichment` as well would
// read every record twice. `parser` is set so a later git pull needs no parser work.
export default src(
  'cisa-vulnrichment',
  'CISA Vulnrichment',
  "CISA's exploitation calls, CVSS, CWE",
  'git',
  'with-cve-list',
  'on',
  { parser: 'cve-json5' },
);
