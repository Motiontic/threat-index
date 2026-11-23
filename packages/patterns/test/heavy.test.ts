import type { Cursor } from '@ti/core/types';
import { describe, expect, it } from 'vitest';
import { fixture } from '../../../test/fixtures';
import { check, fetch } from '../src/heavy';
import { EXAMPLES, sourceWith } from './examples';
import { makeCtx, ranged, reply, route } from './helpers';

const ZIP = EXAMPLES.cwe.heavy.url;
const VERSION_URL = EXAMPLES.cwe.heavy.version.url;
const page = fixture('cwe', 'pattern-version.html');
const head = JSON.parse(fixture('cwe', 'pattern-head.json')) as { headers: Record<string, string> };
const source = sourceWith('cwe');
const at = (value: string, kind: Cursor['kind'] = 'version', etag?: string): Cursor => ({
  kind,
  value,
  ...(etag ? { etag } : {}),
});

describe('heavy with a version page', () => {
  it('check: a ranged GET of version.url and the regex; same version is unchanged', async () => {
    const same = makeCtx({ source, cursor: at('4.17'), routes: [route(VERSION_URL, ranged(page))] });
    expect(await check(same.ctx)).toBe('unchanged');
    expect(same.requests[0]?.headers.range).toBe('bytes=0-4095');
    const newer = makeCtx({ source, cursor: at('4.16'), routes: [route(VERSION_URL, ranged(page))] });
    expect(await check(newer.ctx)).toBe('changed');
    expect(await check(makeCtx({ source, routes: [route(VERSION_URL, ranged(page))] }).ctx)).toBe('changed');
  });

  it('fetch: a change is a job request, nothing is downloaded or parsed', async () => {
    const h = makeCtx({
      source,
      cursor: at('4.16'),
      routes: [route(VERSION_URL, ranged(page, { etag: '"v"' }))],
    });
    const r = await fetch(h.ctx);
    expect(r).toMatchObject({
      items: [],
      receipt: null,
      more: false,
      heavy: { kind: 'big-file', sourceId: 'cwe', url: ZIP, reason: '4.16 → 4.17' },
      nextCursor: { kind: 'version', value: '4.17', etag: '"v"' },
    });
    expect(h.requests.every((q) => q.url === VERSION_URL)).toBe(true);
  });

  it('fetch: no change keeps the cursor', async () => {
    const cur = at('4.17');
    const h = makeCtx({ source, cursor: cur, routes: [route(VERSION_URL, ranged(page))] });
    expect(await fetch(h.ctx)).toMatchObject({ items: [], receipt: null, more: false, nextCursor: cur });
    expect(h.requests).toHaveLength(1);
  });

  it('fetch: a null cursor hands off; jobKind sets the kind; the version bytes can be set', async () => {
    const custom = {
      ...source,
      pull: {
        jobKind: 'epss-diff' as const,
        heavy: { ...EXAMPLES.cwe.heavy, version: { ...EXAMPLES.cwe.heavy.version, bytes: 100 } },
      },
    };
    const h = makeCtx({ source: custom, routes: [route(VERSION_URL, ranged(page))] });
    const r = await fetch(h.ctx);
    expect(r.heavy).toMatchObject({ kind: 'epss-diff', reason: 'none → 4.17' });
    expect(h.requests[0]?.headers.range).toBe('bytes=0-99');
  });

  it('a version that is not on the page is a format error', async () => {
    const h = makeCtx({ source, routes: [route(VERSION_URL, ranged('<p>nothing</p>'))] });
    await expect(check(h.ctx)).rejects.toMatchObject({ code: 'format' });
  });
});

describe('heavy with a validator', () => {
  const plain = { ...source, pull: { heavy: { url: ZIP } } };

  it('check and fetch: HEAD url and its validator', async () => {
    const etag = head.headers.etag ?? '';
    const same = makeCtx({
      source: plain,
      cursor: at(etag, 'etag', etag),
      routes: [route(ZIP, reply(null, 304), 'HEAD')],
    });
    expect(await check(same.ctx)).toBe('unchanged');
    expect(same.requests[0]?.headers['if-none-match']).toBe(etag);
    const changed = makeCtx({
      source: plain,
      cursor: at('"old"', 'etag', '"old"'),
      routes: [route(ZIP, reply(null, 200, head.headers), 'HEAD')],
    });
    const r = await fetch(changed.ctx);
    expect(r.heavy).toMatchObject({ kind: 'big-file', url: ZIP });
    expect(r.nextCursor).toEqual(at(etag, 'etag', etag));
  });

  it('uses Last-Modified when there is no ETag', async () => {
    const h = makeCtx({
      source: plain,
      routes: [route(ZIP, reply(null, 200, { 'last-modified': 'Thu, 08 May 2025 12:00:00 GMT' }), 'HEAD')],
    });
    const r = await fetch(h.ctx);
    expect(r.nextCursor.value).toBe('lm:Thu, 08 May 2025 12:00:00 GMT');
  });

  it('without a validator and without a version is not-configured, so no job runs every time', async () => {
    const h = makeCtx({
      source: plain,
      cursor: at('x', 'etag'),
      routes: [route(ZIP, reply(null, 200), 'HEAD')],
    });
    await expect(check(h.ctx)).rejects.toMatchObject({ code: 'not-configured', retryable: false });
    await expect(fetch(h.ctx)).rejects.toMatchObject({ code: 'not-configured' });
  });
});
