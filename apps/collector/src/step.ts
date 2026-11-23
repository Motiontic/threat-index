import type { RunStatus } from '@ti/core/control';
import { canIngest, displayMode } from '@ti/core/licence';
import { readSourceSettings, unknownFieldsKey } from '@ti/core/settings';
import type { CredentialName, Cursor, ParsedRecord, ParseResult } from '@ti/core/types';
import { databasesFromEnv } from '@ti/db/write';
import { MAX_ITEMS_PER_STEP, type PatternContext, type PatternResult } from '@ti/patterns/types';
import { SOURCE_BY_ID, type SourceConfig } from '@ti/sources/registry';
import { retryDelaySeconds } from './backoff';
import type { StepDeps } from './deps';
import { DEFAULT_USER_AGENT, type Env, type JobMessage, MAX_STEPS_PER_RUN, parseJobMessage } from './env';
import { describeError, isNotConfigured, isPermanent, PermanentError } from './errors';
import { linkDeps } from './link-deps';
import { writeReceipt } from './receipt';

export type StepOutcome =
  | { ack: true; status: RunStatus | 'duplicate' | 'stale' | 'invalid' }
  | { ack: false; delaySeconds: number; error: string };

const PATTERN_TIMEOUT_MS = 300_000;
const MAX_UNKNOWN_FIELDS = 50;
const MAX_FIELD_CHARS = 100;

interface Counts {
  found: number;
  bytes: number;
}

/**
 * Runs one queue message: one small step (≤ 40 items) for one source. Never throws: the outcome says
 * whether to ack or to retry after a delay. See docs/IMPLEMENTATION_PLAN.md §5.
 */
export async function runStep(
  body: unknown,
  attempts: number,
  env: Env,
  deps: StepDeps,
): Promise<StepOutcome> {
  const msg = parseJobMessage(body);
  if (!msg) {
    deps.log('invalid job message');
    return { ack: true, status: 'invalid' };
  }
  const ids = { sourceId: msg.sourceId, runId: msg.runId, step: msg.step };
  try {
    const outcome = await execute(msg, env, deps);
    if (outcome.ack) deps.log('step done', { ...ids, status: outcome.status });
    return outcome;
  } catch (err) {
    const error = describeError(err);
    if (isPermanent(err)) {
      try {
        await finishRun(env, msg, deps, 'failed', error);
        deps.log('step failed', { ...ids, status: 'failed' });
        return { ack: true, status: 'failed' };
      } catch {
        // D1 itself is failing: retry so the run row gets its failure later.
      }
    } else {
      try {
        await env.DB_CONTROL.prepare("UPDATE runs SET error = ?1 WHERE id = ?2 AND status = 'running'")
          .bind(error, msg.runId)
          .run();
      } catch {
        // best effort: the retry will try again
      }
    }
    const delaySeconds = retryDelaySeconds(attempts);
    deps.log('step will retry', { ...ids, attempts, delaySeconds });
    return { ack: false, delaySeconds, error };
  }
}

interface StoredCursor {
  kind: string;
  value: string | null;
  etag: string | null;
}

function sameCursor(stored: StoredCursor | null, from: Cursor | null): boolean {
  if (!stored || !from) return stored === null && from === null;
  return (
    stored.kind === from.kind &&
    (stored.value ?? '') === from.value &&
    (stored.etag ?? null) === (from.etag ?? null)
  );
}

/**
 * Sets the run's final status. Inserts the row if the step never got to; leaves a run that is no longer
 * `running` alone. `counts` add to what earlier steps stored.
 */
async function finishRun(
  env: Env,
  msg: JobMessage,
  deps: StepDeps,
  status: RunStatus,
  error: string | null,
  counts: Counts = { found: 0, bytes: 0 },
): Promise<void> {
  const at = deps.now().toISOString();
  await env.DB_CONTROL.prepare(
    `INSERT INTO runs (id, source_id, started_at, finished_at, status, found, written, bytes, error)
     VALUES (?1, ?2, ?3, ?3, ?4, ?5, 0, ?6, ?7)
     ON CONFLICT(id) DO UPDATE SET status = excluded.status, finished_at = excluded.finished_at,
       found = runs.found + excluded.found, bytes = runs.bytes + excluded.bytes, error = excluded.error
     WHERE runs.status = 'running'`,
  )
    .bind(msg.runId, msg.sourceId, at, status, counts.found, counts.bytes, error)
    .run();
}

async function execute(msg: JobMessage, env: Env, deps: StepDeps): Promise<StepOutcome> {
  const source = SOURCE_BY_ID.get(msg.sourceId);
  if (!source) {
    await finishRun(env, msg, deps, 'failed', 'unknown source');
    return { ack: true, status: 'failed' };
  }
  const db = env.DB_CONTROL;

  // 2. Cursor and run row, in one round trip.
  const [cursorRes, runRes] = await db.batch<Record<string, unknown>>([
    db.prepare('SELECT kind, value, etag FROM cursors WHERE source_id = ?1').bind(source.id),
    db.prepare('SELECT status FROM runs WHERE id = ?1').bind(msg.runId),
  ]);
  const stored = (cursorRes?.results[0] as unknown as StoredCursor | undefined) ?? null;
  const run = (runRes?.results[0] as { status: string } | undefined) ?? null;
  if (run && run.status !== 'running') return { ack: true, status: 'duplicate' };

  // 3. KV override.
  const settings = (await readSourceSettings(env.SETTINGS, [source.id])).get(source.id);
  if (!canIngest(source.licence, settings?.ingest)) {
    await finishRun(env, msg, deps, 'skipped', 'ingest is off');
    return { ack: true, status: 'skipped' };
  }

  // 4. Stale: this step already committed (a redelivery), or another run moved the cursor.
  if (!sameCursor(stored, msg.from)) {
    if (!run) await finishRun(env, msg, deps, 'skipped', 'cursor moved since planning');
    return { ack: true, status: 'stale' };
  }

  // 5.
  if (!run) {
    await db
      .prepare(
        `INSERT INTO runs (id, source_id, started_at, status) VALUES (?1, ?2, ?3, 'running')
         ON CONFLICT(id) DO NOTHING`,
      )
      .bind(msg.runId, source.id, deps.now().toISOString())
      .run();
  }

  // 6.
  const pattern = deps.patternFor(source.pattern);
  const ctx = patternContext(source, msg, env, deps);
  if (msg.step === 0 && (await pattern.check(ctx)) === 'unchanged') {
    await finishRun(env, msg, deps, 'unchanged', null);
    return { ack: true, status: 'unchanged' };
  }

  // 7.
  let result: PatternResult;
  try {
    result = await pattern.fetch(ctx);
  } catch (err) {
    if (isNotConfigured(err)) {
      await finishRun(env, msg, deps, 'skipped', 'source has no pull config yet');
      return { ack: true, status: 'skipped' };
    }
    throw err;
  }
  if (result.items.length > MAX_ITEMS_PER_STEP) {
    throw new PermanentError(`pattern returned ${result.items.length} items (max ${MAX_ITEMS_PER_STEP})`);
  }
  if (result.more && sameCursor(storedFromCursor(result.nextCursor), msg.from)) {
    throw new PermanentError('pattern has more pages but did not advance the cursor');
  }

  const linkOnly = displayMode(source.licence, settings?.display) === 'link';

  // 8. Receipt before any parsing.
  let bytes = 0;
  if (result.receipt || result.items.length > 0) {
    bytes = await writeReceipt(env.BUCKET, {
      sourceId: source.id,
      runId: msg.runId,
      step: msg.step,
      now: deps.now(),
      receipt: result.receipt,
      items: result.items,
      linkOnly,
    });
  }

  // 9. Too big for a Worker: ti-api keeps the cursor with the job and commits it on completion.
  if (result.heavy) {
    await deps.startJob({
      ...result.heavy,
      requestId: `${msg.runId}-${msg.step}`,
      cursor: result.nextCursor,
    });
    await finishRun(env, msg, deps, 'heavy', null, { found: result.items.length, bytes });
    return { ack: true, status: 'heavy' };
  }

  // 10.
  if (!source.parser) {
    await finishRun(env, msg, deps, 'ok', null, { found: result.items.length, bytes });
    return { ack: true, status: 'ok' };
  }

  // 11.
  if (linkOnly) {
    throw new PermanentError('source is link-only and has a parser: no link-only field filter exists yet');
  }
  let parser: Awaited<ReturnType<StepDeps['loadParser']>>;
  try {
    parser = await deps.loadParser(source.parser);
  } catch (err) {
    throw new PermanentError(describeError(err), { cause: err });
  }
  const records: ParsedRecord[] = [];
  const unknown = new Set<string>();
  let failures = 0;
  let firstFailure: unknown;
  for (const item of result.items) {
    try {
      const out = parser.parse(item.body);
      if (Array.isArray(out)) records.push(...out);
      else {
        const res = out as ParseResult<ParsedRecord>;
        records.push(...res.records);
        for (const f of res.unknownFields ?? []) unknown.add(f);
      }
    } catch (err) {
      if (failures === 0) firstFailure = err;
      failures++;
    }
  }
  if (failures > 0 && failures === result.items.length) {
    throw new PermanentError(describeError(firstFailure), { cause: firstFailure });
  }
  const warning =
    failures > 0
      ? `parse failed for ${failures} of ${result.items.length} items: ${describeError(firstFailure)}`.slice(
          0,
          500,
        )
      : null;

  // 12.
  if (unknown.size > 0) await mergeUnknownFields(env, source.id, unknown, deps);

  // 13.
  let written = 0;
  if (records.length > 0) {
    const linked = await deps.link(records, linkDeps(env, deps));
    deps.log('linked', { sourceId: source.id, runId: msg.runId, step: msg.step, docs: linked.docs.length });
    if (linked.rows.length > 0) {
      const res = await deps.writeRows(
        databasesFromEnv(env as unknown as Record<string, unknown>),
        linked.rows,
        {
          priority: 'steady',
          now: deps.now(),
        },
      );
      if (res.deferred) throw new Error('write deferred');
      written = res.written;
    }
  }

  const last = !result.more;
  const committed = await commitCursor(env, source.id, msg, result.nextCursor, deps, {
    found: records.length,
    written,
    bytes,
    last,
    warning,
  });
  if (!committed) {
    deps.log('step already committed by a twin', { sourceId: source.id, runId: msg.runId, step: msg.step });
    return { ack: true, status: 'duplicate' };
  }
  if (last) return { ack: true, status: 'ok' };

  // 14.
  try {
    if (msg.step + 1 > MAX_STEPS_PER_RUN) throw new Error('step limit');
    await env.JOBS.send({
      sourceId: source.id,
      runId: msg.runId,
      step: msg.step + 1,
      from: result.nextCursor,
    });
  } catch {
    await finishRun(env, msg, deps, 'failed', 'continuation not queued');
    return { ack: true, status: 'failed' };
  }
  return { ack: true, status: 'ok' };
}

function storedFromCursor(c: Cursor): StoredCursor {
  return { kind: c.kind, value: c.value, etag: c.etag ?? null };
}

function patternContext(source: SourceConfig, msg: JobMessage, env: Env, deps: StepDeps): PatternContext {
  const credentials: Partial<Record<CredentialName, string>> = {};
  if (env.GITHUB_TOKEN) credentials.github = env.GITHUB_TOKEN;
  if (env.NVD_API_KEY) credentials.nvd = env.NVD_API_KEY;
  return {
    source,
    cursor: msg.from,
    userAgent: env.USER_AGENT || DEFAULT_USER_AGENT,
    fetch: deps.fetch,
    signal: AbortSignal.timeout(PATTERN_TIMEOUT_MS),
    wait: deps.wait,
    log: deps.log,
    now: deps.now,
    runId: msg.runId,
    credentials,
  };
}

/** Adds newly seen field names to unknown-fields:<id>. Diagnostics only: a KV failure never fails the step. */
async function mergeUnknownFields(
  env: Env,
  sourceId: string,
  seen: Set<string>,
  deps: StepDeps,
): Promise<void> {
  try {
    const key = unknownFieldsKey(sourceId);
    const raw = await env.SETTINGS.get(key);
    let prev: { fields: string[]; firstSeen: string } | null = null;
    if (raw) {
      try {
        const j = JSON.parse(raw) as { fields?: unknown; firstSeen?: unknown };
        if (
          Array.isArray(j.fields) &&
          j.fields.every((f) => typeof f === 'string') &&
          typeof j.firstSeen === 'string'
        ) {
          prev = { fields: j.fields as string[], firstSeen: j.firstSeen };
        }
      } catch {
        // a malformed value is replaced
      }
    }
    const fields = [...(prev?.fields ?? [])];
    let added = false;
    for (const name of seen) {
      const f = name.slice(0, MAX_FIELD_CHARS);
      if (fields.length >= MAX_UNKNOWN_FIELDS) break;
      if (!fields.includes(f)) {
        fields.push(f);
        added = true;
      }
    }
    if (!added) return;
    const now = deps.now().toISOString();
    await env.SETTINGS.put(key, JSON.stringify({ fields, firstSeen: prev?.firstSeen ?? now, lastSeen: now }));
  } catch {
    deps.log('unknown fields not saved', { sourceId });
  }
}

/**
 * Compare-and-set: moves the cursor only if it is still `msg.from`. Only then do the run's counts change
 * (and, on the last step, its status), so a redelivered step cannot count twice. False if a twin won.
 */
async function commitCursor(
  env: Env,
  sourceId: string,
  msg: JobMessage,
  next: Cursor,
  deps: StepDeps,
  r: { found: number; written: number; bytes: number; last: boolean; warning: string | null },
): Promise<boolean> {
  const db = env.DB_CONTROL;
  const at = deps.now().toISOString();
  const from = msg.from;
  const cursorStmt = from
    ? db
        .prepare(
          `UPDATE cursors SET kind = ?1, value = ?2, etag = ?3, updated_at = ?4
           WHERE source_id = ?5 AND kind = ?6 AND value IS ?7 AND etag IS ?8`,
        )
        .bind(
          next.kind,
          next.value,
          next.etag ?? null,
          at,
          sourceId,
          from.kind,
          from.value,
          from.etag ?? null,
        )
    : db
        .prepare(
          `INSERT INTO cursors (source_id, kind, value, etag, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT DO NOTHING`,
        )
        .bind(sourceId, next.kind, next.value, next.etag ?? null, at);
  const runStmt = db
    .prepare(
      `UPDATE runs SET found = found + ?1, written = written + ?2, bytes = bytes + ?3,
         status = CASE WHEN ?4 = 1 THEN 'ok' ELSE status END,
         finished_at = CASE WHEN ?4 = 1 THEN ?5 ELSE finished_at END,
         error = COALESCE(?6, CASE WHEN error LIKE 'parse failed%' THEN error END)
       WHERE id = ?7 AND status = 'running' AND changes() > 0`,
    )
    .bind(r.found, r.written, r.bytes, r.last ? 1 : 0, at, r.warning, msg.runId);
  const [cursorRes] = await db.batch([cursorStmt, runStmt]);
  return (cursorRes?.meta.changes ?? 0) > 0;
}
