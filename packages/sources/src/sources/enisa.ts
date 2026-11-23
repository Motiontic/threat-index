import { src } from '../define';

// Not `since` yet: the EUVD search takes only `yyyy-MM-dd` dates (an ISO timestamp gives 400) and pages by a 0-based
// page index, and the `since` pattern sends ISO timestamps and a numeric offset. Until it can, this watches the 100
// most recently updated exploited entries: each 3-hour run sends the new or changed ones. The full EUVD feed waits
// for a `since` option for date-only parameters and page-index paging.
export default src(
  'enisa',
  'ENISA (EUVD + EU KEV)',
  'EU IDs and EU exploited list',
  'fingerprint',
  '3h',
  'ask',
  {
    parser: 'euvd',
    pull: {
      fingerprint: {
        url: 'https://euvdservices.enisa.europa.eu/api/search?exploited=true&page=0&size=100',
        format: 'json',
        itemsPath: 'items',
        key: 'id',
      },
    },
  },
);
