import { src } from '../define';

// A static CSV of about 558 KB with about 897 rows and no ID column. `Title` repeats in 5 rows, so those rows are
// re-sent each run and link as unchanged (the parser's ID keeps them apart). The fingerprint pattern returns at
// most 40 changed rows per step, so the first run walks about 23 steps.
export default src(
  'cfr-tracker',
  'CFR Cyber Operations Tracker',
  'State-sponsored operations',
  'fingerprint',
  'weekly',
  'ask',
  {
    parser: 'cfr-cyber-ops',
    pull: {
      fingerprint: {
        url: 'https://static.cfr.org/cyber-operations/data/cyber-operations-incidents.csv',
        format: 'csv',
        key: 'Title',
      },
    },
  },
);
