/** Cloudflare's rate limiting binding. */
export type RateLimiter = { limit(options: { key: string }): Promise<{ success: boolean }> };

/** ti-mcp bindings, declared by hand (see wrangler.jsonc). */
export interface Env {
  /** ti-api, over a service binding. Reached only through `callApi` (src/api.ts). */
  API: Fetcher;
  /** Tool off-switches: `mcp:tool:<name>:off`. */
  SETTINGS: KVNamespace;
  MCP_TASKS: DurableObjectNamespace;
  /** Per-user and per-IP limits; a missing binding fails open. */
  RL_MCP?: RateLimiter;
  RL_MCP_ANON?: RateLimiter;
  TI_ENV: string;
  /** The public URL of this server, e.g. https://mti.motiontic.com/mcp. */
  MCP_RESOURCE_URL: string;
  /** The Clerk issuer that signs the OAuth access tokens. */
  CLERK_ISSUER: string;
  /** Comma list of browser origins allowed to call /mcp. Empty: none. */
  MCP_ALLOWED_ORIGINS: string;
  /** Comma list of IPv4/IPv6 CIDRs that skip the no-token limit. Unset: Anthropic's published egress. */
  MCP_ANON_EXEMPT_CIDRS?: string;
  /** Signs the identity sent to ti-api (same values as ti-api's; the next one is for rotation). */
  MCP_HMAC_SECRET?: string;
  MCP_HMAC_SECRET_NEXT?: string;
  /** Seals the `requestState` of an elicitation (AES-GCM). Not the HMAC secret. Missing: elicitation is off. */
  MCP_STATE_KEY?: string;
  MCP_STATE_KEY_NEXT?: string;
}
