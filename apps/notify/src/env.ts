/** ti-notify bindings. See docs/IMPLEMENTATION_PLAN.md §10. */
export interface Env {
  DB_SIGNALS: D1Database;
  DB_USERS: D1Database;
  DB_VULNS: D1Database;
  /** Bound for package-advisory matching, which lands later. Nothing reads it yet. */
  DB_ADVISORIES: D1Database;
  DB_WORLD: D1Database;
  EMAIL_FROM: string;
  APP_BASE: string;
  API_BASE: string;
  UNSUBSCRIBE_SECRET: string;
  RESEND_API_KEY?: string;
}

export type NotifyMessage = { kind: 'run-finished'; at: number };

/** Replaceable in tests. */
export interface Deps {
  fetch: typeof fetch;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}
