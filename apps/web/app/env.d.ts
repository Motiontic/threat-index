// Bindings of ti-web, declared by hand (see wrangler.jsonc). `pnpm build` never runs `wrangler types`.
declare namespace Cloudflare {
  interface Env {
    API: Fetcher;
    TI_ENV: string;
  }
}
interface Env extends Cloudflare.Env {}
