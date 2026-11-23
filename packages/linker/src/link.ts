import { NotImplementedError } from '@ti/core/errors';
import type { InboxRow } from '@ti/core/inbox';
import type { ParsedRecord } from '@ti/core/types';

export interface LinkDeps {
  /**
   * Current rows for these keys, for alias lookups and change detection. Each key is an object of the
   * table's primary-key columns, using the real column names. The linker calls this at most once per
   * table per link(); the implementation splits the keys into as many queries as D1's bound-parameter
   * limit needs.
   */
  read(table: string, keys: Record<string, unknown>[]): Promise<Record<string, unknown>[]>;
  /**
   * Cold-vulnerability summary from lookup/vuln/<shard>.json, used to promote a cold flaw: a row shaped
   * like a `vulns` row (same column names). Null if none.
   */
  lookupCold(vulnKey: string): Promise<Record<string, unknown> | null>;
  now(): Date;
  newId(): string;
}

export interface LinkResult {
  /** Every D1 write, including `changes` rows. Only hot-set entities. */
  rows: InboxRow[];
  /** Vulnerability keys whose docs/vuln/<key>.json must be rebuilt. */
  docs: string[];
  /** Cold records left out of D1 (they reach lake/ through the nightly fold). */
  skipped: number;
}

export async function link(_records: ParsedRecord[], _deps: LinkDeps): Promise<LinkResult> {
  throw new NotImplementedError('linker link');
}
