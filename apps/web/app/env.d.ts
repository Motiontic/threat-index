// Bindings of ti-web, declared by hand (see wrangler.jsonc). `pnpm build` never runs `wrangler types`.
declare namespace Cloudflare {
  interface Env {
    API: Fetcher;
    TI_ENV: string;
    DATA_SOURCE?: string;
  }
}
interface Env extends Cloudflare.Env {}
