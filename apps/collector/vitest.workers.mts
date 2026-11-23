import { workerProject } from '../../test/workers-project.mts';

export default workerProject(
  import.meta.dirname,
  'collector',
  'collector',
  ['test/**/*.workers.test.ts'],
  {
    DB_CONTROL: 'control',
    DB_VULNS: 'vulns',
    DB_ADVISORIES: 'advisories',
    DB_SIGNALS: 'signals',
    DB_WORLD: 'world',
  },
  { JOB_HMAC_SECRET: 'test-job-hmac-secret' },
);
