/** Reading a newest-first change list (CSV) and fetching its documents, for `first-load` and `big-file`. */
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import type { ChangeItem } from '@ti/patterns/changelist';
import { fillTemplate, parseCsvLine } from '@ti/patterns/util';
import type { PullConfig } from '@ti/sources/pull';
import { type FetchDeps, fetchDocument, readTextLimited } from './http.ts';
import { mapLimited, rateGate } from './pool.ts';

export const MAX_LIST_DOCS = 10_000;
export const ITEMS_IN_FLIGHT = 8;
export const ITEMS_PER_SECOND = 10;

export type Pair = [time: string, ref: string];
export interface ListLine {
  time: string;
  ref: string;
  ms: number;
}
type ChangelistConfig = NonNullable<PullConfig['changelist']>;

/** A `[time, ref]` JSON pair (a cursor value), or null. */
export function readPair(value: string | undefined): Pair | null {
  if (!value) return null;
  try {
    const v = JSON.parse(value) as unknown;
    if (Array.isArray(v) && typeof v[0] === 'string' && typeof v[1] === 'string') return [v[0], v[1]];
  } catch {
    // not JSON
  }
  return null;
}

/** Orders lines like the pattern's `cmp`: by time, then by ref. */
export const cmpLines = (a: ListLine, b: ListLine): number =>
  a.ms - b.ms || (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0);

const lineOf = (pair: Pair): ListLine => ({ time: pair[0], ref: pair[1], ms: Date.parse(pair[0]) });

/**
 * Reads the list at `path` line by line. Keeps rows whose time parses and whose ref is set, inside the window
 * `(from, to]` (either end open when null). Returns them oldest first.
 */
export async function readChangeList(
  path: string,
  cfg: Pick<ChangelistConfig, 'timeColumn' | 'refColumn'>,
  window: { from: Pair | null; to: Pair | null },
): Promise<{ lines: ListLine[]; unreadable: number }> {
  const from = window.from ? lineOf(window.from) : null;
  const to = window.to ? lineOf(window.to) : null;
  const lines: ListLine[] = [];
  let unreadable = 0;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Number.POSITIVE_INFINITY });
  for await (const raw of rl) {
    if (!raw) continue;
    const cols = parseCsvLine(raw);
    const time = cols[cfg.timeColumn];
    const ref = cols[cfg.refColumn];
    const ms = time ? Date.parse(time) : Number.NaN;
    if (!time || !ref || Number.isNaN(ms)) {
      unreadable++;
      continue;
    }
    const l = { time, ref, ms };
    if (from && !Number.isNaN(from.ms) && cmpLines(l, from) <= 0) continue;
    if (to && !Number.isNaN(to.ms) && cmpLines(l, to) > 0) continue;
    lines.push(l);
  }
  return { lines: lines.sort(cmpLines), unreadable };
}

/** Applies the per-job cap: a first load keeps the newest `MAX_LIST_DOCS`; an update over it fails. */
export function applyCap(
  lines: ListLine[],
  mode: 'first-load' | 'update',
  cap = MAX_LIST_DOCS,
): { lines: ListLine[]; older: number } {
  if (lines.length <= cap) return { lines, older: 0 };
  if (mode === 'update') throw new Error(`too many changes: ${lines.length}`);
  return { lines: lines.slice(lines.length - cap), older: lines.length - cap };
}

export interface FetchedItem {
  /** The document, or null when it was over the size limit (skipped). */
  item: ChangeItem | null;
}

export interface ItemDeps extends FetchDeps {
  now?: () => Date;
}

/** Fetches one item (a deleted document gives `text: null`), or null when it is over 10 MiB. */
export async function fetchItem(
  cfg: Pick<ChangelistConfig, 'itemUrl'>,
  line: Pick<ListLine, 'ref' | 'time'>,
  deps: FetchDeps,
): Promise<ChangeItem | null> {
  const url = fillTemplate(cfg.itemUrl, { ref: line.ref });
  const res = await fetchDocument(url, deps, { goneIsNull: true });
  if (!res) return { ref: line.ref, time: line.time, text: null };
  const text = await readTextLimited(res);
  return text === null ? null : { ref: line.ref, time: line.time, text };
}

/**
 * Fetches every line's document, at most 8 at a time and 10 requests a second. `onItem` gets each document
 * (in input order of completion); an over-size document is counted in `oversize`.
 */
export async function fetchItems(
  cfg: Pick<ChangelistConfig, 'itemUrl'>,
  lines: readonly ListLine[],
  deps: ItemDeps,
  onItem: (item: ChangeItem) => void,
): Promise<{ oversize: number }> {
  const gate = rateGate(ITEMS_PER_SECOND, deps.sleep, deps.now);
  let oversize = 0;
  await mapLimited(lines, ITEMS_IN_FLIGHT, async (line) => {
    await gate();
    const item = await fetchItem(cfg, line, deps);
    if (item) onItem(item);
    else oversize++;
  });
  return { oversize };
}
