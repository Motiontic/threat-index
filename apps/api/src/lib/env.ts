import type { LoadMessage } from '@ti/core/inbox';

export type Bindings = {
  DB_CONTROL: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_USERS: D1Database;
  BUCKET: R2Bucket;
  LOAD: Queue<LoadMessage>;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  CLERK_WEBHOOK_SIGNING_SECRET: string;
  RESEND_WEBHOOK_SECRET: string;
  UNSUBSCRIBE_SECRET: string;
  JOB_HMAC_SECRET: string;
  // Vars (wrangler.jsonc) and secrets for the E2B bridge. Optional: a missing value turns the feature off.
  API_BASE: string | undefined;
  E2B_TEMPLATE: string | undefined;
  R2_BUCKET_NAME: string | undefined;
  E2B_API_KEY: string | undefined;
  R2_ACCOUNT_ID: string | undefined;
  R2_ACCESS_KEY_ID: string | undefined;
  R2_SECRET_ACCESS_KEY: string | undefined;
};
export type Variables = { userId: string };
export type AppEnv = { Bindings: Bindings; Variables: Variables };
