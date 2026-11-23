import { ALL_DBS, workerProject } from '../../test/workers-project.mts';

// Dummy secrets. The Clerk publishable key decodes to "example.clerk.accounts.dev$".
export const API_BINDINGS = {
  CLERK_SECRET_KEY: 'sk_test_dummy',
  CLERK_PUBLISHABLE_KEY: 'pk_test_ZXhhbXBsZS5jbGVyay5hY2NvdW50cy5kZXYk',
  CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_dGVzdC1zaWduaW5nLXNlY3JldA==',
  RESEND_WEBHOOK_SECRET: 'whsec_dGVzdC1yZXNlbmQtc2VjcmV0',
  UNSUBSCRIBE_SECRET: 'test-unsubscribe-secret',
  JOB_HMAC_SECRET: 'test-job-hmac-secret',
  EDGE_HMAC_SECRET: 'test-edge-hmac-secret',
  ADMIN_USER_IDS: 'user_admin',
  E2B_API_KEY: 'e2b_dummy_key',
  R2_ACCOUNT_ID: '0123456789abcdef0123456789abcdef',
  R2_ACCESS_KEY_ID: 'dummy-r2-access-key-id',
  R2_SECRET_ACCESS_KEY: 'dummy-r2-secret-access-key',
};

export default workerProject(
  import.meta.dirname,
  'api',
  'api',
  ['test/**/*.workers.test.ts'],
  ALL_DBS,
  API_BINDINGS,
);
