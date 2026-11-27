import { DurableObject } from 'cloudflare:workers';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/server/validators/cf-worker';
import { logEvent } from '@ti/core/log';
import type { McpIdentity } from '@ti/core/mcp-user';
import type { Env } from '../env';
import { CHECK_OUTPUT_SCHEMA, callerPackages, formatCheck, PRIORITIES, refKey } from '../tools/check-format';
import { credits as formatCredits, rec } from '../tools/common';
import { DEEP_OUTPUT_SCHEMA, DEEP_TEMPLATES, type DeepTemplate, deepRows } from '../tools/deep-format';
import { newTaskId } from './ids';
import { fitPage, MAX_PAGE_ITEMS } from './pages';
import {
  type ApiFn,
  apiVia,
  CHECK_BODY_CAP,
  DEEP_BODY_CAP,
  errorName,
  readJsonCapped,
  readJsonResult,
  retryAfterSeconds,
} from './upstream';

export type TaskKind = 'check' | 'deep_query';
export type TaskStatus = 'working' | 'completed' | 'failed' | 'cancelled';
export type ToolOutcome =
  | { kind: 'ok' }
  | { kind: 'tool_error'; code: string; retryAfter?: number; note?: string; field?: string };

export const CHECK_MAX_RUN_MS = 1_800_000;
export const DEEP_MAX_RUN_MS = 600_000;
const HOUR_MS = 3_600_000;
export const TTL_MS: Record<TaskKind, number> = {
  check: CHECK_MAX_RUN_MS + HOUR_MS,
  deep_query: DEEP_MAX_RUN_MS + HOUR_MS,
};
export const POLL_MS: Record<TaskKind, number> = { check: 10_000, deep_query: 20_000 };
export const MAX_WORKING = 3;
export const MAX_STORED = 20;
export const CHUNK = 1000;
/** ti-api's body cap is 1 MiB; a chunk stays under 900 KB serialised. */
export const CHUNK_BYTES = 900 * 1024;
const MAX_REJECTED = 1000;
const ALARM_MAX_CHUNKS = 5;
const ALARM_MAX_MS = 60_000;
const DEEP_POLL_MS = 15_000;
const MAX_TRIES = 3;
const MAX_TIMEOUT_TRIES = 2;
/** Bump when a table gains a column; the constructor adds what an older object lacks. */
const SCHEMA_VERSION = 2;
const MAX_FAULTS = 3;
const MAX_DEEP_POLL_FAILS = 5;
const MAX_CURSOR_OFFSET = 20_000;
const TOOL_OF = { check: 'mti_check_packages', deep_query: 'mti_deep_query' } as const;
const JOB_ID = /^[0-9A-Z]{26}$/;

interface Row {
  id: string;
  kind: TaskKind;
  status: TaskStatus;
  status_message: string | null;
  created_at: number;
  updated_at: number;
  expires_at: number;
  next_run_at: number | null;
  owner: string;
  scopes: string | null;
  client_id: string | null;
  token_exp: number;
  request_id: string;
  job_id: string | null;
  progress: string;
  outcome: string | null;
  meta: string | null;
  faults: number;
  cancel_job: number;
}

export interface TaskView {
  taskId: string;
  kind: TaskKind;
  status: TaskStatus;
  statusMessage?: string;
  createdAt: number;
  lastUpdatedAt: number;
  ttlMs: number;
  pollIntervalMs: number;
}
export interface PageOut {
  data: Record<string, unknown>;
  /** The offset of the next page, or null on the last one. The caller seals it into a cursor. */
  next: number | null;
}
export type CreateResult =
  | { ok: true; task: TaskView }
  | { ok: false; code: string; retryAfter?: number; field?: string };
export interface GetResult {
  found: boolean;
  task?: TaskView;
  outcome?: ToolOutcome;
  failed?: boolean;
  page?: PageOut;
  /** The task's own request ID (not the poll's), for the text of a failure. */
  requestId?: string;
}

export interface Deps {
  now: () => number;
  api: ApiFn;
  /** When the one alarm really fires for a wanted time. Tests push it out so the alarm only runs when they say. */
  armAt?: (wanted: number) => number;
}

interface CheckProgress {
  next: number;
  tries: number;
  checked: number;
  matched: number;
  done: number;
  summary: Record<string, number>;
  asOf: string | null;
  credits: { source: string; text: string; url: string | null }[];
  notes: string[];
  chunks: number;
  polls: number;
  /** Items stored so far. */
  items: number;
  rejectedKept: number;
  rejectedExtra: number;
  notChecked: number;
  /** Of `notChecked`, the packages whose 200 answer could not be read. */
  unreadable?: number;
  /** True once any try of the current chunk timed out: at most one more try, whatever fails next. */
  timedOut?: boolean;
  /** A deep query's package, so the rows can keep that package's version ranges. */
  deep?: { ecosystem: string; package: string };
}
const emptyProgress = (): CheckProgress => ({
  next: 0,
  tries: 0,
  checked: 0,
  matched: 0,
  done: 0,
  summary: { fix_now: 0, fix_soon: 0, plan: 0, note: 0 },
  asOf: null,
  credits: [],
  notes: [],
  chunks: 0,
  polls: 0,
  items: 0,
  rejectedKept: 0,
  rejectedExtra: 0,
  notChecked: 0,
});

const validator = new CfWorkerJsonSchemaValidator({ draft: '2020-12' });
const props = (schema: unknown) => (schema as { properties: Record<string, { items: unknown }> }).properties;
/** Each stored item is checked against the tool's own output schema when it is written. */
const itemValid = {
  results: validator.getValidator(props(CHECK_OUTPUT_SCHEMA).results?.items as never),
  noRecord: validator.getValidator(props(CHECK_OUTPUT_SCHEMA).noRecord?.items as never),
  rejected: validator.getValidator(props(CHECK_OUTPUT_SCHEMA).rejected?.items as never),
  rows: validator.getValidator(props(DEEP_OUTPUT_SCHEMA).rows?.items as never),
};

/**
 * One Durable Object per user: all of that user's MCP Tasks, their stored input and their results. The work runs
 * here too, by alarm, so a task's state and its work share one strongly consistent store. There is one alarm per
 * object, set to the earliest of every task's next run and expiry; `alarm()` runs everything that is due.
 */
export class McpTask extends DurableObject<Env> {
  /** Replaced in tests, through `runInDurableObject`. */
  deps: Deps = { now: () => Date.now(), api: apiVia(this.env) };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      const sql = ctx.storage.sql;
      sql.exec(`CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, status_message TEXT,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        next_run_at INTEGER, owner TEXT NOT NULL, scopes TEXT, client_id TEXT, token_exp INTEGER NOT NULL,
        request_id TEXT NOT NULL, job_id TEXT, progress TEXT NOT NULL, outcome TEXT, meta TEXT,
        faults INTEGER NOT NULL DEFAULT 0, cancel_job INTEGER NOT NULL DEFAULT 0)`);
      sql.exec(
        'CREATE TABLE IF NOT EXISTS input (task_id TEXT NOT NULL, chunk INTEGER NOT NULL, start INTEGER NOT NULL, data TEXT NOT NULL, orig TEXT NOT NULL, PRIMARY KEY (task_id, chunk))',
      );
      sql.exec(`CREATE TABLE IF NOT EXISTS item (
        task_id TEXT NOT NULL, seq INTEGER NOT NULL, krank INTEGER NOT NULL, prank INTEGER NOT NULL,
        pos INTEGER NOT NULL, ord INTEGER, data TEXT NOT NULL, PRIMARY KEY (task_id, seq))`);
      sql.exec('CREATE INDEX IF NOT EXISTS item_order ON item (task_id, krank, prank, pos, seq)');
      upgradeSchema(sql);
    });
  }

  private get sql() {
    return this.ctx.storage.sql;
  }
  private now(): number {
    return this.deps.now();
  }

  // ---- housekeeping ------------------------------------------------------------------------------------

  /** Deletes every task past its expiry, with its input and results. */
  private purge(): void {
    const now = this.now();
    const due = this.sql.exec('SELECT 1 FROM tasks WHERE expires_at <= ? LIMIT 1', now).toArray();
    if (due.length === 0) return;
    this.ctx.storage.transactionSync(() => {
      const gone = '(SELECT id FROM tasks WHERE expires_at <= ?)';
      this.sql.exec(`DELETE FROM item WHERE task_id IN ${gone}`, now);
      this.sql.exec(`DELETE FROM input WHERE task_id IN ${gone}`, now);
      this.sql.exec('DELETE FROM tasks WHERE expires_at <= ?', now);
    });
  }

  /** Sets the one alarm to the earliest next run or expiry, or removes it when no task is left. */
  private async schedule(): Promise<void> {
    const r = this.sql.exec('SELECT MIN(next_run_at) AS a, MIN(expires_at) AS e FROM tasks').toArray()[0] as {
      a: number | null;
      e: number | null;
    };
    const at = Math.min(r.a ?? Number.POSITIVE_INFINITY, r.e ?? Number.POSITIVE_INFINITY);
    if (!Number.isFinite(at)) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(this.deps.armAt ? this.deps.armAt(at) : Math.max(at, this.now()));
  }

  /** The start of every call: purge, and put the alarm back if it went missing. */
  private async enter(): Promise<void> {
    this.purge();
    if ((await this.ctx.storage.getAlarm()) === null) await this.schedule();
  }

  private row(id: string): Row | null {
    return (this.sql.exec('SELECT * FROM tasks WHERE id = ?', id).toArray()[0] as unknown as Row) ?? null;
  }
  private owned(sub: string, id: string): Row | null {
    const r = this.row(id);
    return r && r.owner === sub && r.expires_at > this.now() ? r : null;
  }
  private view(r: Row): TaskView {
    return {
      taskId: r.id,
      kind: r.kind,
      status: r.status,
      ...(r.status_message ? { statusMessage: r.status_message } : {}),
      createdAt: r.created_at,
      lastUpdatedAt: r.updated_at,
      ttlMs: TTL_MS[r.kind],
      pollIntervalMs: POLL_MS[r.kind],
    };
  }
  private identity(r: Row): McpIdentity | null {
    if (!r.scopes || !r.client_id) return null;
    return { sub: r.owner, scopes: JSON.parse(r.scopes) as string[], clientId: r.client_id };
  }
  private log(r: Row, extra: Record<string, unknown> = {}): void {
    // The first 6 characters of the task ID only. Never the sub, the client, or package names.
    logEvent('info', 'mcp_task', {
      kind: r.kind,
      status: r.status,
      task: r.id.slice(0, 6),
      ms: this.now() - r.created_at,
      ...extra,
    });
  }

  /** Every status change is conditional on `working`. False when something else got there first. */
  private end(
    id: string,
    status: Exclude<TaskStatus, 'working'>,
    outcome: ToolOutcome | null,
    opts: { message?: string; keepRun?: number | null; keepIdentity?: boolean } = {},
  ): boolean {
    const now = this.now();
    const hit = this.sql
      .exec(
        `UPDATE tasks SET status = ?, outcome = ?, status_message = ?, updated_at = ?, next_run_at = ?,
           scopes = CASE WHEN ? THEN scopes ELSE NULL END, client_id = CASE WHEN ? THEN client_id ELSE NULL END
         WHERE id = ? AND status = 'working' RETURNING id`,
        status,
        outcome ? JSON.stringify(outcome) : null,
        opts.message ?? null,
        now,
        opts.keepRun ?? null,
        opts.keepIdentity ? 1 : 0,
        opts.keepIdentity ? 1 : 0,
        id,
      )
      .toArray();
    if (hit.length === 0) return false;
    this.sql.exec('DELETE FROM input WHERE task_id = ?', id);
    if (status !== 'completed' || outcome?.kind !== 'ok')
      this.sql.exec('DELETE FROM item WHERE task_id = ?', id);
    const r = this.row(id);
    if (r) this.log(r, { chunks: (JSON.parse(r.progress) as CheckProgress).chunks });
    return true;
  }
  private toolError(
    id: string,
    code: string,
    extra: { note?: string; retryAfter?: number; field?: string } = {},
  ) {
    return this.end(id, 'completed', { kind: 'tool_error', code, ...extra });
  }
  private fail(id: string): boolean {
    return this.end(id, 'failed', null, { message: 'Internal error' });
  }

  private reserve(
    kind: TaskKind,
    identity: McpIdentity,
    tokenExp: number,
    nextRunAt: number,
    progress: CheckProgress,
    message: string | null = null,
  ): { ok: true; id: string } | { ok: false } {
    const now = this.now();
    const rows = this.sql.exec('SELECT status FROM tasks WHERE expires_at > ?', now).toArray() as {
      status: string;
    }[];
    if (rows.filter((r) => r.status === 'working').length >= MAX_WORKING) return { ok: false };
    if (rows.length >= MAX_STORED) return { ok: false };
    const id = newTaskId();
    this.sql.exec(
      `INSERT INTO tasks (id, kind, status, status_message, created_at, updated_at, expires_at, next_run_at, owner, scopes,
         client_id, token_exp, request_id, progress) VALUES (?, ?, 'working', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      kind,
      message,
      now,
      now,
      now + TTL_MS[kind],
      nextRunAt,
      identity.sub,
      JSON.stringify(identity.scopes),
      identity.clientId,
      tokenExp,
      crypto.randomUUID(),
      JSON.stringify(progress),
    );
    return { ok: true, id };
  }

  // ---- calls from the Worker ---------------------------------------------------------------------------

  async exists(sub: string, taskId: string): Promise<boolean> {
    await this.enter();
    return this.owned(sub, taskId) !== null;
  }

  /**
   * Stores a check of 1,001 or more packages and arms the alarm that runs it. Packages that repeat (the same
   * purl, or the same ecosystem, name and version) are merged first, so a list cannot buy storage or charges
   * with copies. The input is stored in chunks of at most 1,000 packages and 900 KB.
   */
  async createCheck(identity: McpIdentity, tokenExp: number, packages: unknown[]): Promise<CreateResult> {
    await this.enter();
    const seen = new Set<string>();
    const unique: unknown[] = [];
    const origin: number[] = []; // each kept package's position in the caller's list
    for (const [pos, p] of packages.entries()) {
      // The same normalised identity the formatter uses, so PyPI `Foo_Bar` and `foo-bar` merge. A package that
      // cannot be normalised keeps its raw key, so it is still reported as rejected.
      const own = [...callerPackages([p]).values()][0];
      const r = rec(p);
      const key = own
        ? `n|${refKey(own.ref)}`
        : typeof r.purl === 'string'
          ? `p|${r.purl}`
          : JSON.stringify([r.ecosystem, r.name, r.version]);
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(p);
      origin.push(pos);
    }
    const merged = packages.length - unique.length;
    const note = merged > 0 ? `${merged} duplicate packages were merged.` : null;
    const enc = new TextEncoder();
    const chunks: { start: number; data: string; orig: number[] }[] = [];
    let cur: string[] = [];
    let bytes = 0;
    let start = 0;
    const flush = () => {
      if (cur.length === 0) return;
      chunks.push({ start, data: `[${cur.join(',')}]`, orig: origin.slice(start, start + cur.length) });
      start += cur.length;
      cur = [];
      bytes = 0;
    };
    for (const p of unique) {
      const text = JSON.stringify(p);
      const n = enc.encode(text).length + 1;
      if (cur.length >= CHUNK || bytes + n > CHUNK_BYTES) flush();
      cur.push(text);
      bytes += n;
    }
    flush();

    let out: CreateResult | undefined;
    this.ctx.storage.transactionSync(() => {
      const progress = emptyProgress();
      if (note) progress.notes.push(note);
      const res = this.reserve('check', identity, tokenExp, this.now(), progress, note);
      if (!res.ok) {
        out = { ok: false, code: 'too_many_tasks' };
        return;
      }
      for (const [i, c] of chunks.entries())
        this.sql.exec(
          'INSERT INTO input (task_id, chunk, start, data, orig) VALUES (?, ?, ?, ?, ?)',
          res.id,
          i,
          c.start,
          c.data,
          JSON.stringify(c.orig),
        );
      out = { ok: true, task: this.view(this.row(res.id) as Row) };
    });
    if (out?.ok) this.log(this.row(out.task.taskId) as Row, { packages: unique.length, merged });
    await this.schedule();
    return out as CreateResult;
  }

  /** Reserves a slot, starts the job through ti-api, and answers with the task or the reason it did not start. */
  async startDeepQuery(
    identity: McpIdentity,
    tokenExp: number,
    query: { template: string; params: Record<string, string> },
  ): Promise<CreateResult> {
    await this.enter();
    // Orphan guard: a reservation with no job after a minute is ended by the alarm.
    const progress = emptyProgress();
    const { ecosystem, package: pkgName } = query.params;
    if (typeof ecosystem === 'string' && typeof pkgName === 'string')
      progress.deep = { ecosystem, package: pkgName };
    const res = this.reserve('deep_query', identity, tokenExp, this.now() + 60_000, progress);
    if (!res.ok) return { ok: false, code: 'too_many_tasks' };
    await this.schedule();
    const drop = async () => {
      this.sql.exec('DELETE FROM tasks WHERE id = ?', res.id);
      await this.schedule();
    };
    const row = this.row(res.id) as Row;
    let api: Response;
    try {
      api = await this.deps.api(identity, {
        method: 'POST',
        path: '/v1/deep-query',
        body: query,
        requestId: `${row.request_id}-s`,
      });
    } catch {
      await drop();
      return { ok: false, code: 'upstream_unavailable' };
    }
    if (api.status !== 202) {
      const retryAfter = api.status === 429 ? retryAfterSeconds(api) : undefined;
      const name = await errorName(api);
      await drop();
      const code =
        api.status === 409
          ? 'too_many_tasks'
          : api.status === 429
            ? 'rate_limited'
            : api.status === 400
              ? 'invalid_argument'
              : api.status === 501
                ? 'not_available_yet'
                : api.status === 403 && name === 'blocked'
                  ? 'blocked'
                  : api.status === 401 || api.status === 403
                    ? 'internal'
                    : 'upstream_unavailable';
      return {
        ok: false,
        code,
        ...(retryAfter ? { retryAfter } : {}),
        ...(code === 'invalid_argument' ? { field: 'params' } : {}),
      };
    }
    const body = (await readJsonCapped(api, 4096)) as { id?: unknown } | null;
    const jobId = typeof body?.id === 'string' && JOB_ID.test(body.id) ? body.id : null;
    if (!jobId) {
      await drop();
      return { ok: false, code: 'upstream_unavailable' };
    }
    const started = this.sql
      .exec(
        "UPDATE tasks SET job_id = ?, next_run_at = ?, updated_at = ? WHERE id = ? AND status = 'working' RETURNING id",
        jobId,
        this.now() + DEEP_POLL_MS,
        this.now(),
        res.id,
      )
      .toArray();
    if (started.length === 0) {
      // Cancelled while the start was in flight: the job is running, so stop it now (the alarm retries).
      const gone = this.row(res.id);
      if (!gone) return { ok: false, code: 'internal' };
      this.sql.exec(
        'UPDATE tasks SET job_id = ?, cancel_job = 1, next_run_at = ? WHERE id = ?',
        jobId,
        this.now() + DEEP_POLL_MS,
        res.id,
      );
      await this.cancelJob(this.row(res.id) as Row);
      await this.schedule();
      return { ok: true, task: this.view(this.row(res.id) as Row) };
    }
    const stored = this.row(res.id);
    if (!stored) return { ok: false, code: 'internal' };
    this.log(stored, { template: query.template });
    await this.schedule();
    return { ok: true, task: this.view(stored) };
  }

  async get(sub: string, taskId: string): Promise<GetResult> {
    await this.enter();
    const r = this.owned(sub, taskId);
    if (!r) return { found: false };
    const task = this.view(r);
    const requestId = r.request_id;
    if (r.status === 'failed') return { found: true, task, failed: true, requestId };
    if (r.status !== 'completed') return { found: true, task };
    const outcome = JSON.parse(r.outcome ?? '{"kind":"ok"}') as ToolOutcome;
    if (outcome.kind !== 'ok') return { found: true, task, outcome, requestId };
    return { found: true, task, outcome, page: this.pageOf(r, 0) ?? undefined, requestId };
  }

  /** A stored page of a finished task, or null for an unknown, foreign, expired or wrong-kind task. */
  async page(sub: string, taskId: string, kind: TaskKind, offset: number): Promise<PageOut | null> {
    await this.enter();
    const r = this.owned(sub, taskId);
    if (!r || r.kind !== kind || r.status !== 'completed') return null;
    if ((JSON.parse(r.outcome ?? '{}') as ToolOutcome).kind !== 'ok') return null;
    return this.pageOf(r, offset);
  }

  /** Ack. A working check stops after the chunk in flight; a working deep query has its job cancelled. */
  async cancel(sub: string, taskId: string): Promise<{ found: boolean }> {
    await this.enter();
    const r = this.owned(sub, taskId);
    if (!r) return { found: false };
    if (r.status !== 'working') return { found: true };
    // A deep query whose start is still in flight has no job ID yet: the identity is kept so the start can send the
    // DELETE when it returns.
    const isDeep = r.kind === 'deep_query';
    const hasJob = isDeep && r.job_id !== null;
    this.end(r.id, 'cancelled', null, {
      keepRun: hasJob ? this.now() : null,
      keepIdentity: isDeep,
    });
    if (hasJob) {
      this.sql.exec('UPDATE tasks SET cancel_job = 1 WHERE id = ?', r.id);
      // One try now; the alarm retries until the API answers 200 or 404.
      await this.cancelJob(this.row(r.id) as Row);
    }
    await this.schedule();
    return { found: true };
  }

  // ---- pages ---------------------------------------------------------------------------------------------

  /**
   * One page of a finished task's items, read by key: `ord` is the item's place in the final order (set once when
   * the task completes), and `offset` is the `ord` the page starts at.
   */
  private pageOf(r: Row, offset: number): PageOut | null {
    if (!Number.isInteger(offset) || offset < 0 || offset > MAX_CURSOR_OFFSET) return null;
    const meta = JSON.parse(r.meta ?? '{}') as Record<string, any>;
    const total = Number.isInteger(meta.items) ? (meta.items as number) : 0;
    if (offset > total) return null;
    const rows = this.sql
      .exec(
        'SELECT krank, data FROM item WHERE task_id = ? AND ord >= ? ORDER BY ord LIMIT ?',
        r.id,
        offset,
        MAX_PAGE_ITEMS,
      )
      .toArray() as { krank: number; data: string }[];
    const items = rows.map((x) => ({ k: x.krank, d: JSON.parse(x.data) as unknown }));
    const build = (n: number, more: boolean): Record<string, unknown> => {
      const part = items.slice(0, n);
      if (r.kind === 'check')
        return {
          asOf: meta.asOf,
          checked: meta.checked,
          matched: meta.matched,
          summary: meta.summary,
          results: part.filter((i) => i.k === 0).map((i) => i.d),
          noRecord: part.filter((i) => i.k === 1).map((i) => i.d),
          rejected: part.filter((i) => i.k === 2).map((i) => i.d),
          truncated: more || meta.partial === true,
          credits: meta.credits,
          notes: meta.notes,
          nextCursor: null,
        };
      return {
        asOf: meta.asOf,
        template: meta.template,
        rowCount: meta.rowCount,
        truncated: more || meta.truncated === true,
        rows: part.map((i) => ({ untrusted: i.d })),
        credits: meta.credits,
        notes: meta.notes,
        nextCursor: null,
      };
    };
    const { data, kept, more } = fitPage(items, total - offset, build);
    const next = more && offset + kept <= MAX_CURSOR_OFFSET ? offset + kept : null;
    return { data, next };
  }

  /** Gives every item of a finished task its place in the final order, once. */
  private rank(id: string): void {
    this.sql.exec(
      `WITH r AS (SELECT seq AS s, ROW_NUMBER() OVER (ORDER BY krank, prank, pos, seq) - 1 AS n
                  FROM item WHERE task_id = ?)
       UPDATE item SET ord = r.n FROM r WHERE item.task_id = ? AND item.seq = r.s`,
      id,
      id,
    );
  }

  // ---- the alarm -----------------------------------------------------------------------------------------

  override async alarm(): Promise<void> {
    try {
      this.purge();
      const due = this.sql
        .exec(
          'SELECT id FROM tasks WHERE next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at',
          this.now(),
        )
        .toArray() as { id: string }[];
      for (const { id } of due) {
        try {
          await this.step(id);
          this.sql.exec('UPDATE tasks SET faults = 0 WHERE id = ?', id);
        } catch (e) {
          const r = this.row(id);
          if (!r) continue;
          logEvent('warn', 'mcp_task_fault', {
            task: id.slice(0, 6),
            error: e instanceof Error ? e.name : 'unknown',
          });
          const faults = r.faults + 1;
          if (faults >= MAX_FAULTS && r.status === 'working') this.fail(id);
          else
            this.sql.exec(
              'UPDATE tasks SET faults = ?, next_run_at = ? WHERE id = ?',
              faults,
              this.now() + 5000,
              id,
            );
        }
      }
    } finally {
      await this.schedule();
    }
  }

  private async step(id: string): Promise<void> {
    const r = this.row(id);
    if (!r) return;
    if (r.status !== 'working') {
      if (r.cancel_job === 1) await this.cancelJob(r);
      else this.sql.exec('UPDATE tasks SET next_run_at = NULL WHERE id = ?', id);
      return;
    }
    if (r.kind === 'check') await this.stepCheck(r);
    else await this.stepDeep(r);
  }

  /** DELETE the job. 200 or 404 ends the retries and clears the identity; anything else tries again later. */
  private async cancelJob(r: Row): Promise<void> {
    const identity = this.identity(r);
    if (!identity || !r.job_id) {
      this.sql.exec(
        'UPDATE tasks SET cancel_job = 0, next_run_at = NULL, scopes = NULL, client_id = NULL WHERE id = ?',
        r.id,
      );
      return;
    }
    // No call after the token's expiry: the retries stop and the identity is cleared.
    let done = this.now() >= r.token_exp;
    if (!done)
      try {
        const res = await this.deps.api(identity, {
          method: 'DELETE',
          path: `/v1/deep-query/${r.job_id}`,
          requestId: `${r.request_id}-x`,
        });
        await res.body?.cancel().catch(() => {});
        // 401 and 403 are final too: the same identity will not get a different answer.
        done = res.status === 200 || res.status === 404 || res.status === 401 || res.status === 403;
      } catch {
        done = false;
      }
    if (done)
      this.sql.exec(
        'UPDATE tasks SET cancel_job = 0, next_run_at = NULL, scopes = NULL, client_id = NULL WHERE id = ?',
        r.id,
      );
    else this.sql.exec('UPDATE tasks SET next_run_at = ? WHERE id = ?', this.now() + DEEP_POLL_MS, r.id);
  }

  private progressOf(id: string): CheckProgress {
    return JSON.parse((this.row(id) as Row).progress) as CheckProgress;
  }
  private setProgress(id: string, p: CheckProgress, nextRunAt: number | null): boolean {
    return (
      this.sql
        .exec(
          "UPDATE tasks SET progress = ?, next_run_at = ?, updated_at = ? WHERE id = ? AND status = 'working' RETURNING id",
          JSON.stringify(p),
          nextRunAt,
          this.now(),
          id,
        )
        .toArray().length > 0
    );
  }

  // ---- check runner --------------------------------------------------------------------------------------

  /** True when the tool's off-switch is set (the same key the SDK path reads). */
  private async toolOff(kind: TaskKind): Promise<boolean> {
    try {
      const v = await this.env.SETTINGS.get(`mcp:tool:${TOOL_OF[kind]}:off`, { cacheTtl: 60 });
      return v !== null && v !== undefined;
    } catch {
      return false;
    }
  }

  /** Completes a check with what it has: the merged answer so far, `truncated: true` and a note. */
  private finishCheck(r: Row, partial: boolean, note?: string): void {
    const p = this.progressOf(r.id);
    const notes = [...p.notes];
    if (p.rejectedExtra > 0) notes.push(`${p.rejectedExtra} more rejected packages are not listed.`);
    const unreadable = p.unreadable ?? 0;
    if (p.notChecked - unreadable > 0)
      notes.push(
        `${p.notChecked - unreadable} packages were not checked: the answer for them was too large.`,
      );
    if (unreadable > 0)
      notes.push(`${unreadable} packages were not checked: the answer for them could not be read.`);
    if (note) notes.push(note);
    const meta = {
      asOf: p.asOf ?? new Date(this.now()).toISOString(),
      checked: p.checked,
      matched: p.matched,
      summary: p.summary,
      credits: p.credits,
      notes: notes.slice(0, 10),
      partial: partial || p.notChecked > 0,
      items: p.items,
    };
    this.ctx.storage.transactionSync(() => {
      const hit = this.sql
        .exec(
          "UPDATE tasks SET meta = ? WHERE id = ? AND status = 'working' RETURNING id",
          JSON.stringify(meta),
          r.id,
        )
        .toArray();
      if (hit.length === 0) return;
      this.rank(r.id);
      this.end(r.id, 'completed', { kind: 'ok' });
    });
  }

  /**
   * A terminal error. With finished chunks the task completes with the merged partial answer and a note; with
   * none it completes with the tool error.
   */
  private endCheck(r: Row, code: string, note: (done: number) => string, field?: string): void {
    const done = this.progressOf(r.id).done;
    if (done > 0) this.finishCheck(r, true, note(done));
    else this.toolError(r.id, code, { note: note(0), ...(field ? { field } : {}) });
  }

  private async stepCheck(r: Row): Promise<void> {
    const started = this.now();
    let chunks = 0;
    while (chunks < ALARM_MAX_CHUNKS && this.now() - started < ALARM_MAX_MS) {
      const cur = this.row(r.id);
      if (!cur || cur.status !== 'working') return;
      const now = this.now();
      if (now >= cur.created_at + CHECK_MAX_RUN_MS)
        return this.endCheck(cur, 'timeout', (n) => `Time limit reached after ${n} packages.`);
      if (now >= cur.token_exp)
        return this.endCheck(cur, 'timeout', (n) =>
          n > 0 ? `Sign-in expired after ${n} packages.` : 'Sign-in expired.',
        );
      if (await this.toolOff('check')) return void this.toolError(r.id, 'tool_off');
      const live = this.row(r.id);
      if (!live || live.status !== 'working') return;

      const p = this.progressOf(r.id);
      const total = (
        this.sql.exec('SELECT COUNT(*) AS n FROM input WHERE task_id = ?', r.id).one() as { n: number }
      ).n;
      if (p.next >= total) {
        this.finishCheck(cur, false);
        return;
      }
      const identity = this.identity(cur);
      if (!identity) {
        this.endCheck(cur, 'internal', (n) => `The sign-in was lost after ${n} packages.`);
        return;
      }
      const input = this.sql
        .exec('SELECT start, data, orig FROM input WHERE task_id = ? AND chunk = ?', r.id, p.next)
        .one() as { start: number; data: string; orig: string };
      const packages = JSON.parse(input.data) as unknown[];
      const orig = JSON.parse(input.orig) as number[];

      let res: Response | null = null;
      let timedOut = false;
      try {
        res = await this.deps.api(identity, {
          method: 'POST',
          path: '/v1/packages/check',
          body: { packages },
          requestId: `${cur.request_id}-c${p.next}`,
        });
      } catch (e) {
        res = null;
        timedOut = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
      }
      // Cancelled (or ended) while the call was in flight: the answer is dropped.
      const after = this.row(r.id);
      if (!after || after.status !== 'working') {
        await res?.body?.cancel().catch(() => {});
        return;
      }

      if (res?.status === 200) {
        const read = await readJsonResult(res, CHECK_BODY_CAP);
        if (read.ok && read.value !== null && typeof read.value === 'object') {
          if (this.saveChunk(after, p, input.start, packages, orig, read.value)) chunks++;
          if (this.row(r.id)?.status !== 'working') return;
          continue;
        }
        // Charged already: a 200 is never retried, whatever is wrong with the body. The chunk's packages are listed
        // as not checked and the task goes on.
        this.skipChunk(
          after,
          p,
          orig,
          read.ok || read.reason !== 'too_large' ? 'answer_unreadable' : 'answer_too_large',
        );
        chunks++;
        continue;
      }
      if (res && res.status === 429) {
        const retry = retryAfterSeconds(res);
        const name = await errorName(res);
        if (name === 'quota_exceeded') {
          this.finishCheck(after, true, `Daily limit reached after ${p.done} packages.`);
          return;
        }
        const resume = this.now() + retry * 1000;
        if (resume >= after.created_at + CHECK_MAX_RUN_MS)
          this.endCheck(after, 'timeout', (n) => `Time limit reached after ${n} packages.`);
        else this.setProgress(r.id, p, resume);
        return;
      }
      if (res && res.status !== 200) {
        const name =
          res.status === 403 ? await errorName(res) : (await res.body?.cancel().catch(() => {}), null);
        // Terminal errors end through endCheck, so chunks that were charged are never thrown away.
        if (res.status === 403) {
          if (name === 'blocked')
            return this.endCheck(after, 'blocked', (n) => `Account blocked after ${n} packages.`);
          return this.endCheck(
            after,
            'internal',
            (n) => `The MTI API refused the request after ${n} packages.`,
          );
        }
        if (res.status === 401)
          return this.endCheck(
            after,
            'internal',
            (n) => `The MTI API refused the sign-in after ${n} packages.`,
          );
        if (res.status === 400)
          return this.endCheck(
            after,
            'invalid_argument',
            (n) => `The MTI API refused a chunk as invalid after ${n} packages.`,
            'packages',
          );
        if (res.status === 501)
          return this.endCheck(
            after,
            'not_available_yet',
            (n) => `Not available: stopped after ${n} packages.`,
          );
      }
      // Down or a timeout. Three tries a chunk; once any try has timed out (the call may have been charged) one
      // more at most, whatever the next failure is.
      p.tries += 1;
      if (timedOut) p.timedOut = true;
      if (p.tries >= (p.timedOut ? MAX_TIMEOUT_TRIES : MAX_TRIES)) {
        this.endCheck(
          after,
          'upstream_unavailable',
          (n) => `The MTI API was unavailable after ${n} packages.`,
        );
        return;
      }
      this.setProgress(r.id, p, this.now() + 2000 * p.tries);
      return;
    }
    // Out of chunks or time for this alarm: the next one starts at once.
    this.sql.exec("UPDATE tasks SET next_run_at = ? WHERE id = ? AND status = 'working'", this.now(), r.id);
  }

  /** Adds a rejected entry, up to the cap; the rest are only counted. */
  private reject(
    p: CheckProgress,
    put: (x: { index: number; reason: string }) => void,
    e: { index: number; reason: string },
  ) {
    if (p.rejectedKept >= MAX_REJECTED) p.rejectedExtra += 1;
    else {
      p.rejectedKept += 1;
      put(e);
    }
  }

  /** Writes one chunk's items and the new progress in one step, only if the task is still working. */
  private saveChunk(
    r: Row,
    p: CheckProgress,
    base: number,
    packages: unknown[],
    orig: number[],
    body: unknown,
  ): boolean {
    const f = formatCheck(body, packages, this.env);
    const chunk = p.next;
    const asOf =
      typeof f.asOf === 'string' && /^\d{4}-\d{2}-\d{2}/.test(f.asOf) && f.asOf.length <= 40
        ? f.asOf
        : new Date(this.now()).toISOString();
    const next: CheckProgress = {
      ...p,
      next: chunk + 1,
      tries: 0,
      timedOut: false,
      done: p.done + packages.length,
      checked: p.checked + (f.checked ?? packages.length),
      matched: p.matched + (f.matched ?? f.results.length),
      summary: Object.fromEntries(PRIORITIES.map((k) => [k, (p.summary[k] ?? 0) + f.summary[k]])),
      asOf: p.asOf === null || asOf < p.asOf ? asOf : p.asOf,
      credits: mergeCredits(p.credits, f.credits),
      notes: [...new Set([...p.notes, ...f.notes])].slice(0, 9),
      chunks: p.chunks + 1,
    };
    let saved = false;
    this.ctx.storage.transactionSync(() => {
      let seq = chunk * 100_000;
      const rows: [number, number, number, unknown][] = [];
      for (const x of f.results) {
        if (!itemValid.results(x.r).valid) return void this.fail(r.id);
        rows.push([0, PRIORITIES.indexOf(x.r.priority), base + x.index, x.r]);
      }
      for (const x of f.noRecord) {
        if (!itemValid.noRecord(x.n).valid) return void this.fail(r.id);
        rows.push([1, 0, base + x.index, x.n]);
      }
      for (const x of f.rejected)
        this.reject(
          next,
          (e) => {
            const at = orig[e.index] ?? base + e.index;
            rows.push([2, 0, at, { index: at, reason: e.reason }]);
          },
          x,
        );
      for (const row of rows)
        if (row[0] === 2 && !itemValid.rejected(row[3]).valid) return void this.fail(r.id);
      next.items += rows.length;
      if (!this.setProgress(r.id, next, this.now())) return;
      for (const [krank, prank, pos, data] of rows)
        this.sql.exec(
          'INSERT INTO item (task_id, seq, krank, prank, pos, data) VALUES (?, ?, ?, ?, ?, ?)',
          r.id,
          seq++,
          krank,
          prank,
          pos,
          JSON.stringify(data),
        );
      saved = true;
    });
    return saved;
  }

  /** A chunk whose answer was over the byte cap: its packages are listed as not checked, and the task goes on. */
  private skipChunk(
    r: Row,
    p: CheckProgress,
    orig: number[],
    reason: 'answer_too_large' | 'answer_unreadable',
  ): void {
    const n = orig.length;
    const next: CheckProgress = {
      ...p,
      next: p.next + 1,
      tries: 0,
      timedOut: false,
      unreadable: (p.unreadable ?? 0) + (reason === 'answer_unreadable' ? n : 0),
      done: p.done + n,
      chunks: p.chunks + 1,
      notChecked: p.notChecked + n,
    };
    this.ctx.storage.transactionSync(() => {
      let seq = p.next * 100_000;
      const rows: { index: number; reason: string }[] = [];
      for (let i = 0; i < n; i++)
        this.reject(next, (e) => rows.push(e), { index: orig[i] as number, reason });
      next.items += rows.length;
      if (!this.setProgress(r.id, next, this.now())) return;
      for (const e of rows)
        this.sql.exec(
          'INSERT INTO item (task_id, seq, krank, prank, pos, data) VALUES (?, ?, 2, 0, ?, ?)',
          r.id,
          seq++,
          e.index,
          JSON.stringify(e),
        );
    });
  }

  // ---- deep query runner ---------------------------------------------------------------------------------

  private async stepDeep(r: Row): Promise<void> {
    const identity = this.identity(r);
    const now = this.now();
    // Our own limits: end the job and the task, and keep trying to cancel the job if the API does not answer.
    const stop = async (code: string, note?: string) => {
      const ended = this.end(
        r.id,
        'completed',
        { kind: 'tool_error', code, ...(note ? { note } : {}) },
        {
          keepRun: this.now(),
          keepIdentity: true,
        },
      );
      if (ended) {
        this.sql.exec('UPDATE tasks SET cancel_job = 1 WHERE id = ?', r.id);
        await this.cancelJob(this.row(r.id) as Row);
      }
    };
    if (!r.job_id) {
      this.toolError(r.id, 'upstream_unavailable');
      return;
    }
    if (!identity) {
      this.toolError(r.id, 'internal');
      return;
    }
    if (now >= r.created_at + DEEP_MAX_RUN_MS) return stop('timeout');
    if (now >= r.token_exp) return stop('timeout', 'Sign-in expired.');
    if (await this.toolOff('deep_query')) return stop('tool_off');
    {
      const live = this.row(r.id);
      if (!live || live.status !== 'working') return;
    }

    const p = this.progressOf(r.id);
    p.polls += 1;
    let res: Response | null = null;
    try {
      res = await this.deps.api(identity, {
        method: 'GET',
        path: `/v1/deep-query/${r.job_id}`,
        requestId: `${r.request_id}-p${p.polls}`,
      });
    } catch {
      res = null;
    }
    const after = this.row(r.id);
    if (!after || after.status !== 'working') {
      await res?.body?.cancel().catch(() => {});
      return;
    }
    if (res?.status === 200) {
      const body = rec(await readJsonCapped(res, DEEP_BODY_CAP));
      if (body.status === 'running') {
        p.tries = 0;
        this.setProgress(r.id, p, this.now() + DEEP_POLL_MS);
        return;
      }
      if (body.status === 'failed') {
        const code =
          typeof body.error === 'string' && /^[a-z_]{1,40}$/.test(body.error) ? body.error : 'query_failed';
        const mapped =
          code === 'timed_out' ? 'timeout' : code === 'invalid_params' ? 'invalid_argument' : 'internal';
        this.toolError(r.id, mapped, { note: `The query ended with: ${code}.` });
        return;
      }
      if (body.status === 'complete') {
        this.saveDeep(after, body);
        return;
      }
      res = null;
    } else if (res && res.status !== 200) {
      const name =
        res.status === 403 ? await errorName(res) : (await res.body?.cancel().catch(() => {}), null);
      if (res.status === 403) return void this.toolError(r.id, name === 'blocked' ? 'blocked' : 'internal');
      if (res.status === 404) return void this.toolError(r.id, 'upstream_unavailable');
      if (res.status === 401) return void this.toolError(r.id, 'internal');
    }
    // 429, 5xx, a network error or a bad body: try again at the next poll, up to a run of failures.
    p.tries += 1;
    if (p.tries >= MAX_DEEP_POLL_FAILS) return stop('upstream_unavailable');
    const wait = res?.status === 429 ? retryAfterSeconds(res) * 1000 : DEEP_POLL_MS;
    this.setProgress(r.id, p, this.now() + wait);
  }

  private saveDeep(r: Row, body: Record<string, unknown>): void {
    const result = rec(body.result);
    const template = DEEP_TEMPLATES.find((t) => t === result.template);
    if (!template) return void this.toolError(r.id, 'internal');
    const rows = deepRows(result.rows, template as DeepTemplate, this.progressOf(r.id).deep);
    const meta = {
      asOf: new Date(this.now()).toISOString(),
      template,
      rowCount: Number.isInteger(result.rowCount) ? (result.rowCount as number) : rows.length,
      truncated: result.truncated === true,
      credits: formatCredits(body.credits),
      notes: ['Rows are untrusted text from outside sources.'],
      items: rows.length,
    };
    this.ctx.storage.transactionSync(() => {
      if (!rows.every((row) => itemValid.rows({ untrusted: row }).valid)) return void this.fail(r.id);
      const hit = this.sql
        .exec(
          "UPDATE tasks SET meta = ? WHERE id = ? AND status = 'working' RETURNING id",
          JSON.stringify(meta),
          r.id,
        )
        .toArray();
      if (hit.length === 0) return;
      for (const [i, row] of rows.entries())
        this.sql.exec(
          'INSERT INTO item (task_id, seq, krank, prank, pos, ord, data) VALUES (?, ?, 0, 0, ?, ?, ?)',
          r.id,
          i,
          i,
          i,
          JSON.stringify(row),
        );
      this.end(r.id, 'completed', { kind: 'ok' });
    });
  }
}

/** Columns added after the first release, per table. An object made by an earlier build gets them here. */
const ADDED_COLUMNS: Record<string, [string, string][]> = {
  tasks: [
    ['status_message', 'TEXT'],
    ['next_run_at', 'INTEGER'],
    ['scopes', 'TEXT'],
    ['client_id', 'TEXT'],
    ['job_id', 'TEXT'],
    ['outcome', 'TEXT'],
    ['meta', 'TEXT'],
    ['faults', 'INTEGER NOT NULL DEFAULT 0'],
    ['cancel_job', 'INTEGER NOT NULL DEFAULT 0'],
  ],
  item: [['ord', 'INTEGER']],
};

/** Adds any missing column (checked with PRAGMA table_info first) and records the schema version in `meta`. */
export function upgradeSchema(sql: SqlStorage): void {
  sql.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
  for (const [table, cols] of Object.entries(ADDED_COLUMNS)) {
    const have = new Set(
      (sql.exec(`PRAGMA table_info(${table})`).toArray() as { name: string }[]).map((c) => c.name),
    );
    for (const [name, type] of cols)
      if (!have.has(name)) sql.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
  sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)", String(SCHEMA_VERSION));
  // item_ord indexes a column an old table may only just have gained.
  sql.exec('CREATE INDEX IF NOT EXISTS item_ord ON item (task_id, ord)');
}

function mergeCredits(
  a: { source: string; text: string; url: string | null }[],
  b: { source: string; text: string; url: string | null }[],
) {
  const seen = new Set(a.map((c) => JSON.stringify(c)));
  const out = [...a];
  for (const c of b) {
    const k = JSON.stringify(c);
    if (!seen.has(k) && out.length < 20) {
      seen.add(k);
      out.push(c);
    }
  }
  return out;
}
