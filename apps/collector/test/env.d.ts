import type { Env as CollectorEnv } from '../src/env';

// Types `env` from `cloudflare:workers` in the Workers tests as the collector's bindings.
declare global {
  namespace Cloudflare {
    interface Env extends CollectorEnv {}
  }
}
