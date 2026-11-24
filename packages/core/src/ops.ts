// Shapes and admin checks for the /ops report (ti-api builds it, ti-web renders it).
export interface OpsReport {
  generatedAt: string;
  sources: {
    id: string;
    cadence: string;
    ingest: boolean;
    lastSuccess: string | null;
    /** `reason` is the run's error or skip reason (first 200 characters). */
    lastRun: { status: string; startedAt: string; reason?: string | null } | null;
    failed7d: number;
    deadLettered7d: number;
    late: boolean;
  }[];
  budget: {
    day: string;
    d1Writes: number;
    d1Limit: number;
    emailsSent: number;
    emailCap: number;
    queueOps: number;
    r2ClassA: number;
  };
  queues: { name: 'ti-jobs' | 'ti-jobs-dlq' | 'ti-load'; backlog: number | null; oldest: string | null }[];
  jobs: {
    byStatus: Record<string, number>;
    recent: {
      id: string;
      kind: string;
      status: string;
      sourceId: string | null;
      createdAt: string;
      finishedAt: string | null;
      error: string | null;
    }[];
  };
  deadLetters: { runId: string; sourceId: string; finishedAt: string | null; error: string }[];
}

const ADMIN_ID = /^user_[A-Za-z0-9]{1,64}$/;
const MAX_ADMINS = 20;

/** A comma list of Clerk user ids. Malformed entries are dropped; at most 20 are kept. */
export function parseAdminIds(raw?: string): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => ADMIN_ID.test(s))
    .slice(0, MAX_ADMINS);
}

/** An empty list means no admin. */
export function isAdmin(ids: readonly string[], userId?: string): boolean {
  return Boolean(userId) && ids.includes(userId as string);
}
