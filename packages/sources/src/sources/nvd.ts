import { NVD_NOTICE } from '@ti/core/licence';
import { src } from '../define';

export default src('nvd', 'NVD', 'CVSS scores and affected products', 'since', '3h', 'on', {
  credit: NVD_NOTICE,
  parser: 'nvd',
  // 5 requests per 30 s without a key; the key (`NVD_API_KEY`) is optional.
  rateLimit: { perMinute: 8 },
  pull: {
    since: {
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      startParam: 'lastModStartDate',
      endParam: 'lastModEndDate',
      offsetParam: 'startIndex',
      limitParam: 'resultsPerPage',
      itemsPath: 'vulnerabilities',
      idPath: 'cve.id',
      totalPath: 'totalResults',
      maxWindowDays: 120,
      lookbackDays: 7,
      auth: { header: 'apiKey', credential: 'nvd' },
    },
  },
});
