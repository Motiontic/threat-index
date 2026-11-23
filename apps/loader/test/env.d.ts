import type { Env as LoaderEnv } from '../src/consume';

// Types `env` from `cloudflare:workers` in the Workers tests as the loader's bindings.
declare global {
  namespace Cloudflare {
    interface Env extends LoaderEnv {}
  }
}
