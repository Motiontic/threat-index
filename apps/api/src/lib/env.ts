export type Bindings = {
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_USERS: D1Database;
  BUCKET: R2Bucket;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  CLERK_WEBHOOK_SIGNING_SECRET: string;
  RESEND_WEBHOOK_SECRET: string;
  UNSUBSCRIBE_SECRET: string;
  JOB_HMAC_SECRET: string;
};
export type Variables = { userId: string };
export type AppEnv = { Bindings: Bindings; Variables: Variables };
