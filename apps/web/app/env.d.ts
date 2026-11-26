// Bindings of ti-web, declared by hand (see wrangler.jsonc). `pnpm build` never runs `wrangler types`.
declare namespace Cloudflare {
  interface Env {
    API: Fetcher;
    /** ti-mcp, reached only for /mcp and the OAuth metadata path (workers/app.ts). */
    MCP: Fetcher;
    /** "1" forwards /mcp to ti-mcp; anything else answers 404 there. A var. */
    MCP_ENABLED?: string;
    /** Per-IP page limit; a missing binding fails open. */
    RL_PAGES?: { limit(options: { key: string }): Promise<{ success: boolean }> };
    /** Worker secret shared with ti-api: signs the client IP forwarded to it. */
    EDGE_HMAC_SECRET?: string;
    /** Comma list of Clerk user ids who may see /ops (a var set at deploy). */
    ADMIN_USER_IDS?: string;
    TI_ENV: string;
    /** The public site URL (a var set at deploy from TI_APP_URL[_STAGING]). Canonical links and the workers.dev redirect use it. */
    SITE_ORIGIN?: string;
    DATA_SOURCE?: string;
    /** Clerk's public key (a var, set at deploy) and secret key (a Worker secret). */
    CLERK_PUBLISHABLE_KEY?: string;
    CLERK_SECRET_KEY?: string;
    /** `fake` is honoured only with fixtures data and TI_ENV=local. */
    AUTH_MODE?: string;
  }
}
interface Env extends Cloudflare.Env {}
