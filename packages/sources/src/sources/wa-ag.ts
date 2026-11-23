import { src } from '../define';

// Pattern is `fingerprint`, not `since`: Socrata needs a `$where` clause, which `since` can't send.
export default src('wa-ag', 'Washington AG', 'Breach notices', 'fingerprint', 'daily', 'ask', {
  parser: 'wa-ag',
  pull: {
    fingerprint: {
      url: 'https://data.wa.gov/resource/sb4j-ca4h.json?$order=datesubmitted%20DESC,id%20DESC&$limit=5000',
      format: 'json',
      key: 'id',
    },
  },
});
