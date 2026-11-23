import type { WritePriority } from '@ti/core/budget';
import type { JobRequest } from '@ti/core/control';
import type { InboxRow } from '@ti/core/inbox';
import type { ParsedRecord } from '@ti/core/types';
import { type DatabaseMap, type WriteResult, writeRows } from '@ti/db/write';
import { type LinkDeps, type LinkResult, link } from '@ti/linker/link';
import { loadParser, type ParserModule } from '@ti/parsers/load';
import { patternFor } from '@ti/patterns/by-name';
import type { Pattern } from '@ti/patterns/types';
import type { PatternName } from '@ti/sources/registry';
import { ulid } from 'ulid';
import type { Env } from './env';
import { startHeavyJob } from './heavy';

export interface StepDeps {
  patternFor(name: PatternName): Pick<Pattern, 'check' | 'fetch'>;
  loadParser(name: string): Promise<ParserModule>;
  link(records: ParsedRecord[], deps: LinkDeps): Promise<LinkResult>;
  writeRows(
    dbs: DatabaseMap,
    rows: InboxRow[],
    opts: { priority: WritePriority; now?: Date },
  ): Promise<WriteResult>;
  startJob(req: JobRequest): Promise<{ jobId?: string }>;
  fetch: typeof fetch;
  wait(ms: number): Promise<void>;
  now(): Date;
  newId(): string;
  log(msg: string, extra?: Record<string, unknown>): void;
}

/** JSON-line logging: callers pass ids, counts and status only. */
export function logLine(msg: string, extra: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ msg, ...extra }));
}

/** The real modules. `wait` is `scheduler.wait`, which does not use CPU time. */
export function defaultDeps(env: Env): StepDeps {
  return {
    patternFor,
    loadParser,
    link,
    writeRows,
    startJob: (req) => startHeavyJob(env, req, new Date()),
    fetch: (input, init) => globalThis.fetch(input, init),
    wait: (ms) => scheduler.wait(ms),
    now: () => new Date(),
    newId: ulid,
    log: logLine,
  };
}
