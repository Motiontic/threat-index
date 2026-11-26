import type { LoadMessage } from '@ti/core/inbox';
import type { McpIdentity } from '@ti/core/mcp-user';

/** Cloudflare's rate limiting binding. */
export type RateLimiter = { limit(options: { key: string }): Promise<{ success: boolean }> };

export type Bindings = {
  DB_CONTROL: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_USERS: D1Database;
  BUCKET: R2Bucket;
  LOAD: Queue<LoadMessage>;
  DB_WORLD: D1Database;
  DB_SIGNALS: D1Database;
  SETTINGS: KVNamespace;
  /** Producers used only for `metrics()` on the /ops page. */
  JOBS: Queue | undefined;
  JOBS_DLQ: Queue | undefined;
  /** Rate limit bindings; a missing one fails open. */
  RL_PUBLIC: RateLimiter | undefined;
  RL_USER: RateLimiter | undefined;
  RL_DEEP: RateLimiter | undefined;
  /** Shared with ti-web: verifies the client IP it forwards. Unset: forwarded IPs are ignored. */
  EDGE_HMAC_SECRET: string | undefined;
  /** Comma list of Clerk user ids allowed to read /v1/admin/ops. */
  ADMIN_USER_IDS: string | undefined;
  CLERK_SECRET_KEY: string;
  CLERK_PUBLISHABLE_KEY: string;
  CLERK_WEBHOOK_SIGNING_SECRET: string;
  RESEND_WEBHOOK_SECRET: string;
  UNSUBSCRIBE_SECRET: string;
  JOB_HMAC_SECRET: string;
  /** Verifies the signed identity ti-mcp sends (current and next, for rotation). Unset: MCP calls are refused. */
  MCP_HMAC_SECRET?: string;
  MCP_HMAC_SECRET_NEXT?: string;
  /** The public site URL (a var). */
  SITE_ORIGIN?: string;
  // Vars (wrangler.jsonc) and secrets for the E2B bridge. Optional: a missing value turns the feature off.
  API_BASE: string | undefined;
  E2B_TEMPLATE: string | undefined;
  R2_BUCKET_NAME: string | undefined;
  /** Deployment name (`production` or `staging`); namespaces the shared Cache API keys. */
  TI_ENV: string | undefined;
  E2B_API_KEY: string | undefined;
  R2_ACCOUNT_ID: string | undefined;
  R2_ACCESS_KEY_ID: string | undefined;
  R2_SECRET_ACCESS_KEY: string | undefined;
};
export type Variables = {
  userId: string;
  requestId: string;
  limited?: boolean;
  /** Set by `mcpIdentity` when the call carries a verified MCP assertion. */
  mcp?: McpIdentity;
};
export type AppEnv = { Bindings: Bindings; Variables: Variables };
