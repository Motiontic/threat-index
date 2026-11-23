// Types `env` from `cloudflare:workers` in the Workers tests: the six D1 databases.
declare global {
  namespace Cloudflare {
    interface Env {
      DB_CONTROL: D1Database;
      DB_VULNS: D1Database;
      DB_ADVISORIES: D1Database;
      DB_SIGNALS: D1Database;
      DB_WORLD: D1Database;
      DB_USERS: D1Database;
    }
  }
}

export {};
