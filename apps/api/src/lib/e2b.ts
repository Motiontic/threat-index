/**
 * E2B launcher: SDK path. Spec §1 evidence (e2b 2.64.0):
 *  - `apps/api/test/e2b-sdk.workers.test.ts` imports `e2b` under workerd with a stubbed fetch. `Sandbox.create`
 *    reaches the stub as `POST https://api.e2b.app/v2/sandboxes` and `commands.run` reaches the envd host
 *    (`https://sandbox.e2b.app/process.Process/Start`); no missing Node module, `node:http2`, `eval` or
 *    `new Function` error (the only rejection comes from the canned reply). HTTP/2 needed no fallback.
 *  - `wrangler deploy --dry-run --env staging` bundles the api with the SDK (size in PROOF.md).
 *  - The installed SDK's docs: `CommandHandle.disconnect()` leaves the command running; command
 *    `timeoutMs: 0` disables the command timeout.
 * The REST path was not built.
 */

import type { JobRequest } from '@ti/core/control';
import type { InboxManifest } from '@ti/core/inbox';
import { inboxChunkKey, MAX_ROWS_PER_CHUNK } from '@ti/core/inbox';
import type { Bindings } from './env';

export const JOB_TIMEOUT_MS = 50 * 60 * 1000; // hard limit; E2B Hobby sandboxes live at most 1 h
export const STALE_AFTER_MS = 55 * 60 * 1000; // active rows older than this become timed_out
/**
 * The launch command. The SDK does not pass the image's `ENV`, so nothing set in the Dockerfile reaches it:
 * `launch.mjs` sets the job process's heap (`JOB_HEAP_MB` in e2b/jobs/src/launch.ts) and reports a crash.
 */
export const JOB_COMMAND = 'node /app/launch.mjs';
export const MAX_ACTIVE_JOBS = 5;
export const MAX_CHUNKS = 5000;
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const E2B_REQUEST_TIMEOUT_MS = 30_000;

/** Kinds that work on one source (`JobRequest['kind']`). */
export const SOURCE_JOB_KINDS = ['first-load', 'epss-diff', 'big-file'] as const;
/**
 * Kinds that work on the whole data set. Only `nightly-fold` and `search-index` run on the collector's daily
 * crons (apps/collector/src/daily-jobs.ts); `affected-backfill` is started by an operator.
 */
export const GLOBAL_JOB_KINDS = ['nightly-fold', 'search-index', 'affected-backfill'] as const;
export type GlobalJobKind = (typeof GLOBAL_JOB_KINDS)[number];
// `echo` exists only in the API and the sandbox
export type ApiJobKind = JobRequest['kind'] | GlobalJobKind | 'echo' | 'deep-query';
/** Kinds whose sandbox job is implemented. The work that implements a kind adds it here. */
export const ENABLED_JOB_KINDS: readonly ApiJobKind[] = [
  'echo',
  'first-load',
  'epss-diff',
  'big-file',
  'nightly-fold',
  'search-index',
  'affected-backfill',
  'deep-query',
];

/** Mirrors `Job` in e2b/jobs/src/types.ts. */
export interface SandboxJob {
  id: string;
  kind: ApiJobKind;
  sourceId?: string;
  url?: string;
  /** `YYYY-MM-DD` (UTC): the day a global job works on. */
  day?: string;
  apiBase: string;
  hmac: string;
}
export interface LaunchedSandbox {
  sandboxId: string;
  start(job: SandboxJob): Promise<void>;
}
export interface JobLauncher {
  create(opts: { timeoutMs: number; metadata: Record<string, string> }): Promise<LaunchedSandbox>;
  kill(sandboxId: string): Promise<void>; // resolves if the sandbox is gone or unknown
}

const TEMPLATE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** The callback origin: `https:` with path `/` (`http:` only for localhost). Returns the origin or null. */
export function parseApiBase(value: string | undefined): string | null {
  if (!value) return null;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return null;
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) return null;
  if (u.pathname !== '/' || u.search || u.hash || u.username || u.password) return null;
  return u.origin;
}

/** A short, key-free description of an E2B failure, for logs and `jobs.error`. */
export function describeE2bError(err: unknown, secrets: (string | undefined)[] = []): string {
  const e = err as { name?: unknown; status?: unknown; message?: unknown } | null;
  const name = typeof e?.name === 'string' ? e.name : 'Error';
  let msg = typeof e?.message === 'string' ? e.message : String(err);
  for (const s of secrets) if (s) msg = msg.split(s).join('[redacted]');
  msg = msg
    .replace(/e2b_[A-Za-z0-9]+/g, '[redacted]')
    .replace(/\s+/g, ' ')
    .slice(0, 200);
  const status = typeof e?.status === 'number' ? ` ${e.status}` : '';
  return `${name}${status}: ${msg}`;
}

/** The public site origin passed to sandboxes as `SITE_ORIGIN` (an optional var). Null when unset or unusable. */
export function siteOriginFromEnv(env: Bindings): string | null {
  const value = (env as { SITE_ORIGIN?: string }).SITE_ORIGIN;
  return parseApiBase(value);
}

export function launcherFromEnv(env: Bindings): JobLauncher | null {
  const apiKey = env.E2B_API_KEY;
  const template = env.E2B_TEMPLATE;
  if (!apiKey || !template || !TEMPLATE_RE.test(template)) return null;
  const apiBase = parseApiBase(env.API_BASE);
  if (apiBase === null) return null;
  const apiHost = new URL(apiBase).host;
  const wrap = (err: unknown): Error => new Error(describeE2bError(err, [apiKey]));
  const siteOrigin = siteOriginFromEnv(env);
  return {
    async create({ timeoutMs, metadata }) {
      // Loaded here so the SDK never runs at Worker start-up or on routes that don't launch.
      const { Sandbox } = await import('e2b');
      let sbx: Awaited<ReturnType<typeof Sandbox.create>>;
      try {
        sbx = await Sandbox.create(template, {
          apiKey,
          timeoutMs,
          metadata,
          requestTimeoutMs: E2B_REQUEST_TIMEOUT_MS,
          // The backfill reads and writes through the MTI API only; the job checks that nothing else answers.
          ...(metadata.kind === 'affected-backfill'
            ? { network: { allowOut: [apiHost], denyOut: ({ allTraffic }) => [allTraffic] } }
            : {}),
        });
      } catch (err) {
        throw wrap(err);
      }
      return {
        sandboxId: sbx.sandboxId,
        async start(job) {
          try {
            const handle = await sbx.commands.run(JOB_COMMAND, {
              background: true,
              envs: { JOB_JSON: JSON.stringify(job), ...(siteOrigin ? { SITE_ORIGIN: siteOrigin } : {}) },
              cwd: '/app',
              timeoutMs: 0,
              requestTimeoutMs: E2B_REQUEST_TIMEOUT_MS,
            });
            await handle.disconnect();
          } catch (err) {
            throw wrap(err);
          }
        },
      };
    },
    async kill(sandboxId) {
      const { Sandbox } = await import('e2b');
      try {
        await Sandbox.kill(sandboxId, { apiKey, requestTimeoutMs: E2B_REQUEST_TIMEOUT_MS });
      } catch (err) {
        throw wrap(err);
      }
    },
  };
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** ULID: 10 characters of millisecond time, 16 of randomness (Crockford base32), sortable by time. */
export function newJobId(now: Date = new Date()): string {
  let t = now.getTime();
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const rand = crypto.getRandomValues(new Uint8Array(16));
  let r = '';
  for (const b of rand) r += CROCKFORD[b % 32];
  return time + r;
}

export function parseManifest(
  text: string,
  jobId: string,
  _kind: ApiJobKind,
): { manifest: InboxManifest } | { error: string } {
  if (new TextEncoder().encode(text).length > MAX_MANIFEST_BYTES) return { error: 'manifest too large' };
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { error: 'manifest is not JSON' };
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data))
    return { error: 'manifest is not an object' };
  const m = data as Record<string, unknown>;
  if (m.jobId !== jobId) return { error: 'jobId does not match' };
  if (typeof m.createdAt !== 'string') return { error: 'createdAt missing' };
  if (!Array.isArray(m.chunks)) return { error: 'chunks is not a list' };
  if (m.chunks.length > MAX_CHUNKS) return { error: 'too many chunks' };
  const seen = new Set<string>();
  const chunks: InboxManifest['chunks'] = [];
  for (let n = 0; n < m.chunks.length; n++) {
    const c = m.chunks[n] as Record<string, unknown> | null;
    if (typeof c !== 'object' || c === null) return { error: `chunk ${n} is not an object` };
    if (typeof c.key !== 'string' || c.key !== inboxChunkKey(jobId, n))
      return { error: `chunk ${n} has a bad key` };
    if (seen.has(c.key)) return { error: `chunk ${n} repeats a key` };
    seen.add(c.key);
    if (!Number.isInteger(c.rows) || (c.rows as number) < 1 || (c.rows as number) > MAX_ROWS_PER_CHUNK)
      return { error: `chunk ${n} has bad rows` };
    chunks.push({ key: c.key, rows: c.rows as number });
  }
  return { manifest: { jobId, createdAt: m.createdAt, chunks } };
}
