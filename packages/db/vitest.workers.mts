import { ALL_DBS, workerProject } from '../../test/workers-project.mts';

// The schema tests need every database, so this project borrows the API's bindings.
const BINDINGS = {
  CLERK_SECRET_KEY: 'sk_test_dummy',
  CLERK_PUBLISHABLE_KEY: 'pk_test_ZXhhbXBsZS5jbGVyay5hY2NvdW50cy5kZXYk',
  CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_dGVzdC1zaWduaW5nLXNlY3JldA==',
  RESEND_WEBHOOK_SECRET: 'whsec_dGVzdC1yZXNlbmQtc2VjcmV0',
  UNSUBSCRIBE_SECRET: 'test-unsubscribe-secret',
  JOB_HMAC_SECRET: 'test-job-hmac-secret',
};

export default workerProject(
  import.meta.dirname,
  'db',
  'api',
  ['test/**/*.workers.test.ts'],
  ALL_DBS,
  BINDINGS,
);
