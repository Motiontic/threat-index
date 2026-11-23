import type { Cursor } from '@ti/core/types';
import { SOURCE_BY_ID } from '@ti/sources/registry';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check, fetch } from '../src/since';
import { EXAMPLES, sourceWith } from './examples';
import { makeCtx, NOW, reply, route } from './helpers';

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_RE = /^https:\/\/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?/;
const source = sourceWith('nvd');
const ts = (value: string): Cursor => ({ kind: 'timestamp', value });
const START = '2025-05-01T00:00:00.000Z';
const NOW_ISO = NOW.toISOString();

const page0 = fixture('nvd', 'pattern-page-0.json');
const page1 = fixture('nvd', 'pattern-page-1.json');

function byOffset(req: { url: string }) {
  const offset = new URL(req.url).searchParams.get('startIndex');
  return new Response(offset === '0' ? page0 : page1);
}
const params = (url: string) => Object.fromEntries(new URL(url).searchParams);

describe('since', () => {
  it('check: asks for one item and reads totalResults', async () => {
    const some = makeCtx({ source, cursor: ts(START), routes: [route(NVD_RE, reply(page0))] });
    expect(await check(some.ctx)).toBe('changed');
    expect(params(some.requests[0]?.url ?? '')).toMatchObject({
      lastModStartDate: START,
      lastModEndDate: NOW_ISO,
      resultsPerPage: '1',
      startIndex: '0',
    });
    const none = makeCtx({
      source,
      cursor: ts(START),
      routes: [route(NVD_RE, reply(JSON.stringify({ totalResults: 0, vulnerabilities: [] })))],
    });
    expect(await check(none.ctx)).toBe('unchanged');
  });

  it('check: without totalPath any item means changed; a cursor at now is unchanged without a request', async () => {
    const noTotal = { ...source, pull: { since: { ...EXAMPLES.nvd.since, totalPath: undefined } } };
    const a = makeCtx({ source: noTotal, cursor: ts(START), routes: [route(NVD_RE, reply(page0))] });
    expect(await check(a.ctx)).toBe('changed');
    const b = makeCtx({ source, cursor: ts(NOW_ISO) });
    expect(await check(b.ctx)).toBe('unchanged');
    expect((await fetch(b.ctx)).nextCursor.value).toBe(NOW_ISO);
    expect(b.requests).toHaveLength(0);
  });

  it('check: no cursor, a mid-run cursor, or a capped window is changed without a request', async () => {
    const a = makeCtx({ source });
    const mid = ts(JSON.stringify({ start: START, end: NOW_ISO, offset: 2 }));
    const b = makeCtx({ source, cursor: mid });
    const c = makeCtx({ source, cursor: ts('2025-01-01T00:00:00.000Z') });
    expect([await check(a.ctx), await check(b.ctx), await check(c.ctx)]).toEqual([
      'changed',
      'changed',
      'changed',
    ]);
    expect(a.requests.length + b.requests.length + c.requests.length).toBe(0);
  });

  it('fetch: one page at a time, the window end becomes the cursor when it finishes', async () => {
    const routes = [route(NVD_RE, byOffset)];
    const h = makeCtx({ source, cursor: ts(START), runId: 'r', credentials: { nvd: 'KEY' }, routes });
    const r1 = await fetch(h.ctx);
    expect(r1.items.map((i) => i.id)).toEqual(['CVE-2025-5000', 'CVE-2025-5001']);
    expect(r1.more).toBe(true);
    expect(JSON.parse(r1.nextCursor.value)).toEqual({ start: START, end: NOW_ISO, offset: 2 });
    expect(params(h.requests[0]?.url ?? '').resultsPerPage).toBe('40');
    // Each body is the document cut to one entry.
    const body = r1.items[0]?.body as { vulnerabilities: unknown[]; totalResults: number };
    expect(body.vulnerabilities).toHaveLength(1);
    expect(body.totalResults).toBe(3);
    expect(r1.receipt).toMatchObject({ runId: 'r', contentType: 'application/x-ndjson' });

    const h2 = makeCtx({ source, cursor: r1.nextCursor, routes });
    const r2 = await fetch(h2.ctx);
    expect(r2.items.map((i) => i.id)).toEqual(['CVE-2025-5002']);
    expect(r2).toMatchObject({ more: false, nextCursor: ts(NOW_ISO) });
    expect(params(h2.requests[0]?.url ?? '').startIndex).toBe('2');
  });

  it('fetch: an empty finished window moves the cursor; a capped one says more', async () => {
    const empty = reply(JSON.stringify({ totalResults: 0, vulnerabilities: [] }));
    const a = makeCtx({ source, cursor: ts(START), routes: [route(NVD_RE, empty)] });
    expect(await fetch(a.ctx)).toMatchObject({
      items: [],
      receipt: null,
      more: false,
      nextCursor: ts(NOW_ISO),
    });
    const b = makeCtx({ source, cursor: ts('2025-01-01T00:00:00.000Z'), routes: [route(NVD_RE, empty)] });
    const r = await fetch(b.ctx);
    // 120 days after 1 Jan is 1 May.
    expect(r.nextCursor.value).toBe('2025-05-01T00:00:00.000Z');
    expect(r.more).toBe(true);
    expect(params(b.requests[0]?.url ?? '').lastModEndDate).toBe('2025-05-01T00:00:00.000Z');
  });

  it('fetch: sends apiKey to NVD only, and nothing without a credential', async () => {
    const a = makeCtx({
      source,
      cursor: ts(START),
      credentials: { nvd: 'KEY-1' },
      routes: [route(NVD_RE, byOffset)],
    });
    await fetch(a.ctx);
    expect(a.requests[0]?.headers.apikey).toBe('KEY-1');
    expect(a.requests.every((q) => new URL(q.url).origin === 'https://services.nvd.nist.gov')).toBe(true);
    const b = makeCtx({ source, cursor: ts(START), routes: [route(NVD_RE, byOffset)] });
    await fetch(b.ctx);
    expect(b.requests[0]?.headers.apikey).toBeUndefined();
    expect(JSON.stringify(a.logs)).not.toContain('KEY-1');
  });

  it('fetch: a null cursor is a first load at now, unless lookbackDays is set', async () => {
    const a = makeCtx({ source });
    const r = await fetch(a.ctx);
    expect(r.heavy).toMatchObject({ kind: 'first-load', sourceId: 'nvd' });
    expect(r.nextCursor).toEqual(ts(NOW_ISO));
    expect(a.requests).toHaveLength(0);

    const look = { ...source, pull: { since: { ...EXAMPLES.nvd.since, lookbackDays: 2 } } };
    const b = makeCtx({ source: look, routes: [route(NVD_RE, byOffset)] });
    const r2 = await fetch(b.ctx);
    expect(r2.heavy).toBeUndefined();
    expect(params(b.requests[0]?.url ?? '').lastModStartDate).toBe('2025-05-19T12:00:00.000Z');
    expect(r2.items).toHaveLength(2);
  });

  it('fetch: a page over the size limit is a big-file hand-off', async () => {
    const h = makeCtx({
      source,
      cursor: ts(START),
      routes: [route(NVD_RE, reply('x', 200, { 'content-length': String(9 * 1024 * 1024) }))],
    });
    const r = await fetch(h.ctx);
    expect(r.heavy?.kind).toBe('big-file');
    expect(r.nextCursor).toEqual(ts(NOW_ISO));
  });

  it('fetch: heavy: true with jobKind epss-diff hands off on a change without paging', async () => {
    const epss = {
      ...(SOURCE_BY_ID.get('epss') as NonNullable<ReturnType<typeof SOURCE_BY_ID.get>>),
      pull: { since: EXAMPLES.nvd.since, jobKind: 'epss-diff' as const },
    };
    const h = makeCtx({ source: epss, cursor: ts(START), routes: [route(NVD_RE, reply(page0))] });
    const r = await fetch(h.ctx);
    expect(r.items).toEqual([]);
    expect(r.receipt).toBeNull();
    expect(r.heavy).toMatchObject({ kind: 'epss-diff', sourceId: 'epss', url: NVD });
    expect(r.nextCursor).toEqual(ts(NOW_ISO));
    expect(h.requests).toHaveLength(1);
    const quiet = makeCtx({
      source: epss,
      cursor: ts(START),
      routes: [route(NVD_RE, reply(JSON.stringify({ totalResults: 0, vulnerabilities: [] })))],
    });
    expect((await fetch(quiet.ctx)).heavy).toBeUndefined();
  });
});
