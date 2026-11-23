export interface Env {
  DB_CONTROL: D1Database;
  DB_VULNS: D1Database;
  DB_ADVISORIES: D1Database;
  DB_SIGNALS: D1Database;
  DB_WORLD: D1Database;
  BUCKET: R2Bucket;
  SETTINGS: KVNamespace;
  JOBS: Queue<JobMessage>;
  NOTIFY: Queue<{ kind: 'run-finished'; at: number }>;
  USER_AGENT: string;
}

export interface JobMessage {
  sourceId: string;
  runId: string;
  step: number;
}
