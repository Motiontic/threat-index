import { workerProject } from '../../test/workers-project.mts';

export default workerProject(
  import.meta.dirname,
  'notify',
  'notify',
  ['test/**/*.workers.test.ts'],
  { DB_SIGNALS: 'signals', DB_USERS: 'users', DB_VULNS: 'vulns', DB_WORLD: 'world' },
  { UNSUBSCRIBE_SECRET: 'test-unsubscribe-secret' },
);
