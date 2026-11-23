// Bindings of ti-web, declared by hand (see wrangler.jsonc). `pnpm build` never runs `wrangler types`.
declare namespace Cloudflare {
  interface Env {
    API: Fetcher;
    TI_ENV: string;
    DATA_SOURCE?: string;
    /** Clerk's public key (a var, set at deploy) and secret key (a Worker secret). */
    CLERK_PUBLISHABLE_KEY?: string;
    CLERK_SECRET_KEY?: string;
    /** `fake` is honoured only with fixtures data and TI_ENV=local. */
    AUTH_MODE?: string;
  }
}
interface Env extends Cloudflare.Env {}
