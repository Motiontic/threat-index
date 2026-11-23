import type { Env as NotifyEnv } from '../src/env';

// Types `env` from `cloudflare:workers` in the Workers tests as notify's bindings.
declare global {
  namespace Cloudflare {
    interface Env extends NotifyEnv {}
  }
}
