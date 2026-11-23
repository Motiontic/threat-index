import type { Cursor } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { type ChangeItem, check, fetch, MAX_RANGE_READS } from '../src/changelist';
import { EXAMPLES, sourceWith } from './examples';
import { makeCtx, ranged, reply, route } from './helpers';

const LIST = 'https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv';
const ITEMS = /osv-vulnerabilities\.storage\.googleapis\.com\/.+\.json$/;
const csv = fixture('osv', 'pattern-modified_id.csv');
const record = fixture('osv', 'pattern-record.json');
const source = sourceWith('osv');
const at = (time: string, ref: string, etag?: string): Cursor => ({
  kind: 'timestamp',
  value: JSON.stringify([time, ref]),
  ...(etag ? { etag } : {}),
});
const VALIDATOR = '"list-v1"';

describe('changelist', () => {
  it('check: HEAD with the validator; 304 or the same validator is unchanged, a new one changed', async () => {
    const cur = at('2025-05-20T23:00:00Z', 'npm/GHSA-2025-1019', VALIDATOR);
    const a = makeCtx({ source, cursor: cur, routes: [route(LIST, reply(null, 304), 'HEAD')] });
    expect(await check(a.ctx)).toBe('unchanged');
    expect(a.requests[0]).toMatchObject({ method: 'HEAD' });
    expect(a.requests[0]?.headers['if-none-match']).toBe(VALIDATOR);
    const b = makeCtx({
      source,
      cursor: cur,
      routes: [route(LIST, reply(null, 200, { etag: '"list-v2"' }), 'HEAD')],
    });
    expect(await check(b.ctx)).toBe('changed');
  });

  it('check: no cursor, or a mid-run cursor (no validator), is changed without a request', async () => {
    const a = makeCtx({ source });
    const b = makeCtx({ source, cursor: at('2025-05-20T23:00:00Z', 'x') });
    expect(await check(a.ctx)).toBe('changed');
    expect(await check(b.ctx)).toBe('changed');
    expect(a.requests.length + b.requests.length).toBe(0);
  });

  it('fetch with nothing new keeps the cursor and returns no receipt', async () => {
    const cur = at('2025-05-20T23:00:00Z', 'npm/GHSA-2025-1019', VALIDATOR);
    const h = makeCtx({ source, cursor: cur, routes: [route(LIST, ranged(csv))] });
    expect(await fetch(h.ctx)).toMatchObject({ items: [], receipt: null, more: false, nextCursor: cur });
  });

  it('fetch: new lines come oldest-first, ties broken by ref, each fetched from itemUrl', async () => {
    const cur = at('2025-05-18T19:28:00Z', 'npm/GHSA-2025-1015');
    const h = makeCtx({
      source,
      cursor: cur,
      runId: 'r1',
      routes: [route(LIST, ranged(csv, { etag: VALIDATOR })), route(ITEMS, reply(record))],
    });
    const r = await fetch(h.ctx);
    // Two lines share 2025-05-19T21:14:00Z: Go/GO-2025-0003 sorts before npm/GHSA-2025-1017.
    const order = r.items.map((i) => i.id);
    expect(order.indexOf('Go/GO-2025-0003')).toBeLessThan(order.indexOf('npm/GHSA-2025-1017'));
    expect(order).toHaveLength(4);
    expect(order[order.length - 1]).toBe('npm/GHSA-2025-1019');
    expect(r.items[0]?.body).toMatchObject({ text: record } satisfies Partial<ChangeItem>);
    expect(h.requests.map((q) => q.url)).toContain(
      'https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-2025-1019.json',
    );
    expect(r).toMatchObject({ more: false });
    expect(r.nextCursor).toEqual(at('2025-05-20T23:00:00Z', 'npm/GHSA-2025-1019', VALIDATOR));
    expect(r.nextCursor.kind).toBe('timestamp');
    expect(r.receipt).toMatchObject({ runId: 'r1', contentType: 'application/x-ndjson' });
    expect(String(r.receipt?.body).trim().split('\n')).toHaveLength(4);
  });

  it('fetch: 404 and 410 for an item give text: null', async () => {
    const cur = at('2025-05-20T22:00:00Z', 'a/b');
    const h = makeCtx({
      source,
      cursor: cur,
      routes: [
        route(LIST, ranged(csv, { etag: VALIDATOR })),
        route(/npm\/GHSA-2025-1019\.json$/, reply('', 404)),
        route(/PYSEC-2025-1018\.json$/, reply('', 410)),
      ],
    });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => (i.body as ChangeItem).text)).toEqual([null, null]);
    expect(r.receipt).toBeNull();
  });

  it('fetch: skips and counts unreadable lines', async () => {
    const bad = `not-a-date,x/y\n,\nsolo\n${csv}`;
    const h = makeCtx({
      source,
      cursor: at('2025-05-20T22:30:00Z', 'a/b'),
      routes: [route(LIST, ranged(bad)), route(ITEMS, reply(record))],
    });
    const r = await fetch(h.ctx);
    expect(r.items.map((i) => i.id)).toEqual(['npm/GHSA-2025-1019']);
    expect(h.logs.find((l) => l.msg.includes('skipped'))?.extra).toEqual({ skipped: 3 });
  });

  it('fetch: over 40 new gives 40 and more (no validator yet), then the rest', async () => {
    const lines = Array.from(
      { length: 100 },
      (_, i) =>
        `2025-05-20T${String(23 - Math.floor(i / 60)).padStart(2, '0')}:${String(59 - (i % 60)).padStart(2, '0')}:00Z,npm/GHSA-${1000 - i}`,
    );
    const big = `${lines.join('\n')}\n`;
    const cur = at('2025-05-19T00:00:00Z', 'npm/GHSA-0');
    const routes = [route(LIST, ranged(big, { etag: VALIDATOR })), route(ITEMS, reply(record))];
    const r1 = await fetch(makeCtx({ source, cursor: cur, routes }).ctx);
    expect(r1.items).toHaveLength(40);
    expect(r1.more).toBe(true);
    expect(r1.nextCursor.etag).toBeUndefined();
    expect(r1.items[0]?.id).toBe('npm/GHSA-901');
    const h2 = makeCtx({ source, cursor: r1.nextCursor, routes });
    expect(await check(h2.ctx)).toBe('changed');
    const r2 = await fetch(h2.ctx);
    expect(r2.items).toHaveLength(40);
    expect(r2.items[0]?.id).toBe('npm/GHSA-941');
    const r3 = await fetch(makeCtx({ source, cursor: r2.nextCursor, routes }).ctx);
    expect(r3.items).toHaveLength(20);
    expect(r3).toMatchObject({ more: false });
    expect(r3.nextCursor.etag).toBe(VALIDATOR);
  });

  it('fetch: reads a list across ranges, carrying partial lines over', async () => {
    const cur = at('2025-05-18T19:28:00Z', 'npm/GHSA-2025-1015');
    const small = { ...source, pull: { changelist: { ...EXAMPLES.osv.changelist, rangeBytes: 200 } } };
    const h = makeCtx({
      source: small,
      cursor: cur,
      routes: [route(LIST, ranged(csv)), route(ITEMS, reply(record))],
    });
    const r = await fetch(h.ctx);
    expect(r.items).toHaveLength(4);
    const lists = h.requests.filter((q) => q.url === LIST);
    expect(lists.map((q) => q.headers.range)).toEqual(['bytes=0-199', 'bytes=200-399']);
  });

  it('fetch: no boundary within 4 ranges is a big-file hand-off on the list', async () => {
    const cur = at('2024-01-01T00:00:00Z', 'a/b');
    const small = { ...source, pull: { changelist: { ...EXAMPLES.osv.changelist, rangeBytes: 100 } } };
    const h = makeCtx({
      source: small,
      cursor: cur,
      routes: [route(LIST, ranged(csv, { etag: VALIDATOR }))],
    });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([]);
    expect(r.heavy).toMatchObject({ kind: 'big-file', url: LIST, sourceId: 'osv' });
    expect(r.nextCursor).toEqual(at('2025-05-20T23:00:00Z', 'npm/GHSA-2025-1019', VALIDATOR));
    expect(h.requests.filter((q) => q.url === LIST)).toHaveLength(MAX_RANGE_READS);
  });

  it('fetch: a null cursor is a first load at the newest line', async () => {
    const h = makeCtx({ source, routes: [route(LIST, ranged(csv, { etag: VALIDATOR }))] });
    const r = await fetch(h.ctx);
    expect(r.heavy).toMatchObject({ kind: 'first-load', url: LIST });
    expect(r.items).toEqual([]);
    expect(r.nextCursor).toEqual(at('2025-05-20T23:00:00Z', 'npm/GHSA-2025-1019', VALIDATOR));
    expect(h.requests).toHaveLength(1);
  });

  it('fetch: a source with heavy hands off with its job kind and downloads no items', async () => {
    const heavy = { ...source, heavy: true };
    const h = makeCtx({
      source: heavy,
      cursor: at('2025-05-18T19:28:00Z', 'a/b'),
      routes: [route(LIST, ranged(csv, { etag: VALIDATOR }))],
    });
    const r = await fetch(h.ctx);
    expect(r.heavy?.kind).toBe('big-file');
    expect(h.requests.every((q) => q.url === LIST)).toBe(true);
  });
});
