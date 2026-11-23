import type { Bindings } from '../src/lib/env';

// Types `env` from `cloudflare:workers` in the Workers tests as the API's bindings.
declare global {
  namespace Cloudflare {
    interface Env extends Bindings {}
  }
}
