import { src } from '../define';

// The "All" tab (gid=1190662839) of Project Zero's "0day In the Wild" sheet. The export is a CSV of about 260 KB with
// about 414 CVE rows and many empty rows; the fingerprint pattern returns at most 40 changed rows per step, so the
// first run walks about 11 steps.
export default src(
  'project-zero',
  'Project Zero 0-day sheet',
  'Zero-days exploited',
  'fingerprint',
  'weekly',
  'ask',
  {
    parser: 'project-zero',
    pull: {
      fingerprint: {
        url: 'https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=1190662839',
        format: 'csv',
        key: 'CVE',
      },
    },
  },
);
