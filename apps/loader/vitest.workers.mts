import { workerProject } from '../../test/workers-project.mts';

// The loader's wrangler config binds five databases (no users), R2 and the ti-load consumer.
export default workerProject(import.meta.dirname, 'loader', 'loader', ['test/**/*.workers.test.ts'], {
  DB_CONTROL: 'control',
  DB_VULNS: 'vulns',
  DB_ADVISORIES: 'advisories',
  DB_SIGNALS: 'signals',
  DB_WORLD: 'world',
});
