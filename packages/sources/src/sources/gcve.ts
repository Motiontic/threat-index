import { src } from '../define';

// Exploitation sightings from the GCVE Vulnerability-Lookup instance. A daily run sees at most the 100 newest
// sightings. Backfilling older sightings and the cross-ID correlations are later work.
export default src('gcve', 'GCVE', 'Cross-ID links', 'fingerprint', 'daily', 'ask', {
  parser: 'gcve-sighting',
  pull: {
    fingerprint: {
      url: 'https://db.gcve.eu/api/sighting/?type=exploited&per_page=100',
      format: 'json',
      itemsPath: 'data',
      key: 'uuid',
    },
  },
});
