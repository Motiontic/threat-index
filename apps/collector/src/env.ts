import type { Cursor } from '@ti/core/types';

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
  /** ti-api, which starts E2B jobs. */
  API?: Fetcher;
  /** Signs calls to ti-api. Never sent. */
  JOB_HMAC_SECRET?: string;
  /** Watchdog email: all three of these must be set to send it. */
  OPS_EMAIL?: SendEmail;
  OPS_EMAIL_TO?: string;
  OPS_EMAIL_FROM?: string;
  USER_AGENT?: string;
  /** Contact address for sources that demand one (SEC). Falls back to the one inside USER_AGENT. */
  CONTACT_EMAIL?: string;
  /** Optional credentials, handed to patterns as `PatternContext.credentials`. */
  GITHUB_TOKEN?: string;
  NVD_API_KEY?: string;
}

/** Repo URL, no contact address. Used when USER_AGENT is not set. */
export const DEFAULT_USER_AGENT = 'ThreatIndex/0.1 (+https://github.com/Motiontic/threat-index)';

/** A run takes at most this many steps (messages), counting from 0. */
export const MAX_STEPS_PER_RUN = 500;

export interface JobMessage {
  sourceId: string;
  runId: string;
  step: number;
  /** The cursor this step starts from (null for a source that has none yet). */
  from: Cursor | null;
}

const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const CURSOR_KINDS: readonly string[] = ['commit', 'timestamp', 'etag', 'version'];

function parseCursor(v: unknown): Cursor | null | undefined {
  if (v === null) return null;
  if (typeof v !== 'object' || Array.isArray(v)) return undefined;
  const c = v as Record<string, unknown>;
  if (typeof c.kind !== 'string' || !CURSOR_KINDS.includes(c.kind)) return undefined;
  if (typeof c.value !== 'string') return undefined;
  if (c.etag !== undefined && typeof c.etag !== 'string') return undefined;
  const out: Cursor = { kind: c.kind as Cursor['kind'], value: c.value };
  if (c.etag !== undefined) out.etag = c.etag;
  return out;
}

/** Null unless the body is a current-format job message. Messages queued before `from` existed fail. */
export function parseJobMessage(body: unknown): JobMessage | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const m = body as Record<string, unknown>;
  if (typeof m.sourceId !== 'string' || m.sourceId === '' || m.sourceId.length > 100) return null;
  if (typeof m.runId !== 'string' || !ULID.test(m.runId)) return null;
  if (!Number.isInteger(m.step) || (m.step as number) < 0 || (m.step as number) > MAX_STEPS_PER_RUN) {
    return null;
  }
  const from = parseCursor(m.from);
  if (from === undefined) return null;
  return { sourceId: m.sourceId, runId: m.runId, step: m.step as number, from };
}
